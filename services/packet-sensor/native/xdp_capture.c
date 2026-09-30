/* AF_XDP capture shim for packet-sensor (Track A).
 * Linked against libxdp + libbpf; exposes a minimal C API for Python ctypes.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/mman.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "xdp_capture.h"

#define DEFAULT_FRAME_SIZE 2048
#define DEFAULT_NUM_FRAMES 4096

struct xdp_cap_session {
	struct xsk_umem *umem;
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	void *umem_area;
	size_t umem_size;
	uint32_t frame_size;
	uint32_t num_frames;
	uint32_t queue_id;
	int ifindex;
	int xsks_map_fd;
	uint32_t xdp_flags;
	struct bpf_object *bpf_obj;
	struct bpf_program *xdp_prog;
	uint64_t user_rx_frames;
};

static char g_last_error[256];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	const char *debug = getenv("XDP_DEBUG");
	if (!debug || (debug[0] != '1' && debug[0] != 'y' && debug[0] != 'Y'))
		return 0;
	(void)level;
	return vfprintf(stderr, format, args);
}

static void set_last_error(const char *step, int err)
{
	if (err)
		snprintf(g_last_error, sizeof(g_last_error), "%s: %s", step, strerror(-err));
	else
		snprintf(g_last_error, sizeof(g_last_error), "%s failed", step);
}

const char *xdp_cap_last_error(void)
{
	return g_last_error;
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
	if (!map)
		return -1;
	return bpf_map__fd(map);
}

static int populate_fq(struct xdp_cap_session *sess)
{
	uint32_t idx = 0;
	uint32_t ret;

	ret = xsk_ring_prod__reserve(&sess->fq, sess->num_frames, &idx);
	if (ret != sess->num_frames)
		return -1;

	for (uint32_t i = 0; i < sess->num_frames; i++)
		*xsk_ring_prod__fill_addr(&sess->fq, idx + i) =
			(uint64_t)i * sess->frame_size;

	xsk_ring_prod__submit(&sess->fq, sess->num_frames);
	return 0;
}

static int read_kernel_stats(struct xdp_cap_session *sess, uint64_t *rx,
			     uint64_t *redirected, uint64_t *pass)
{
	(void)sess;
	if (rx)
		*rx = 0;
	if (redirected)
		*redirected = 0;
	if (pass)
		*pass = 0;
	return 0;
}

xdp_cap_session *xdp_cap_open(const char *ifname, int queue_id,
			      const char *bpf_obj_path, int xdp_mode,
			      int frame_size, int num_frames)
{
	struct xdp_cap_session *sess;
	struct xsk_umem_config umem_cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = DEFAULT_FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct xsk_socket_config xsk_cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.bind_flags = XDP_COPY,
	};
	struct bpf_program *prog;
	int err;
	__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

	if (!ifname || !bpf_obj_path)
		return NULL;

	if (frame_size <= 0)
		frame_size = DEFAULT_FRAME_SIZE;
	if (num_frames <= 0)
		num_frames = DEFAULT_NUM_FRAMES;
	if (xdp_mode != 0)
		xdp_flags |= XDP_FLAGS_SKB_MODE;

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return NULL;

	sess->frame_size = (uint32_t)frame_size;
	sess->num_frames = (uint32_t)num_frames;
	sess->queue_id = (uint32_t)queue_id;
	sess->ifindex = if_nametoindex(ifname);
	if (!sess->ifindex) {
		free(sess);
		return NULL;
	}

	umem_cfg.frame_size = sess->frame_size;
	sess->umem_size = (size_t)sess->frame_size * sess->num_frames;
	sess->umem_area =
		mmap(NULL, sess->umem_size, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (sess->umem_area == MAP_FAILED) {
		free(sess);
		return NULL;
	}

	libbpf_set_print(libbpf_print_fn);

	sess->bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (!sess->bpf_obj) {
		munmap(sess->umem_area, sess->umem_size);
		free(sess);
		return NULL;
	}

	err = bpf_object__load(sess->bpf_obj);
	if (err) {
		set_last_error("bpf_object__load", err);
		bpf_object__close(sess->bpf_obj);
		munmap(sess->umem_area, sess->umem_size);
		free(sess);
		return NULL;
	}

	sess->xsks_map_fd = map_fd_by_name(sess->bpf_obj, "xsks_map");
	if (sess->xsks_map_fd < 0) {
		set_last_error("xsks_map", -ENOENT);
		bpf_object__close(sess->bpf_obj);
		munmap(sess->umem_area, sess->umem_size);
		free(sess);
		return NULL;
	}

	prog = bpf_object__find_program_by_name(sess->bpf_obj, "xdp_redirect_prog");
	if (!prog) {
		set_last_error("xdp_redirect_prog", -ENOENT);
		bpf_object__close(sess->bpf_obj);
		munmap(sess->umem_area, sess->umem_size);
		free(sess);
		return NULL;
	}

	sess->xdp_flags = (uint32_t)xdp_flags;
	err = bpf_xdp_attach(sess->ifindex, bpf_program__fd(prog), sess->xdp_flags, NULL);
	if (err) {
		set_last_error("bpf_xdp_attach", err);
		bpf_object__close(sess->bpf_obj);
		munmap(sess->umem_area, sess->umem_size);
		free(sess);
		return NULL;
	}
	sess->xdp_prog = prog;

	err = xsk_umem__create(&sess->umem, sess->umem_area, sess->umem_size,
			       &sess->fq, &sess->cq, &umem_cfg);
	if (err) {
		set_last_error("xsk_umem__create", err);
		xdp_cap_close(sess);
		return NULL;
	}

	err = xsk_socket__create(&sess->xsk, ifname, sess->queue_id, sess->umem,
				 &sess->rx, NULL, &xsk_cfg);
	if (err) {
		set_last_error("xsk_socket__create", err);
		xdp_cap_close(sess);
		return NULL;
	}

	err = xsk_socket__update_xskmap(sess->xsk, sess->xsks_map_fd);
	if (err) {
		set_last_error("xsk_socket__update_xskmap", err);
		xdp_cap_close(sess);
		return NULL;
	}

	if (populate_fq(sess) != 0) {
		set_last_error("populate_fq", -ENOMEM);
		xdp_cap_close(sess);
		return NULL;
	}

	return sess;
}

int xdp_cap_recv(xdp_cap_session *sess, unsigned char *buf, int buf_size,
		 int timeout_ms)
{
	uint32_t idx = 0;
	uint32_t rcvd;
	struct pollfd pfd;
	int ret;

	if (!sess || !buf || buf_size <= 0)
		return -1;

	rcvd = xsk_ring_cons__peek(&sess->rx, 1, &idx);
	if (!rcvd) {
		if (xsk_ring_prod__needs_wakeup(&sess->fq))
			(void)xsk_socket__fd(sess->xsk);

		pfd.fd = xsk_socket__fd(sess->xsk);
		pfd.events = POLLIN;
		ret = poll(&pfd, 1, timeout_ms);
		if (ret <= 0)
			return 0;

		rcvd = xsk_ring_cons__peek(&sess->rx, 1, &idx);
		if (!rcvd)
			return 0;
	}

	uint64_t addr = xsk_ring_cons__rx_desc(&sess->rx, idx)->addr;
	uint32_t len = xsk_ring_cons__rx_desc(&sess->rx, idx)->len;
	uint64_t orig = xsk_umem__extract_addr(addr);
	uint64_t offset = xsk_umem__extract_offset(addr);

	if ((int)len > buf_size)
		len = (uint32_t)buf_size;

	memcpy(buf, (uint8_t *)sess->umem_area + orig + offset, len);

	xsk_ring_cons__release(&sess->rx, 1);

	uint32_t fq_idx = 0;
	if (xsk_ring_prod__reserve(&sess->fq, 1, &fq_idx) == 1) {
		*xsk_ring_prod__fill_addr(&sess->fq, fq_idx) = orig;
		xsk_ring_prod__submit(&sess->fq, 1);
	}

	sess->user_rx_frames++;
	return (int)len;
}

int xdp_cap_stats(xdp_cap_session *sess, uint64_t *rx, uint64_t *redirected,
		  uint64_t *pass, uint64_t *user_rx)
{
	if (!sess)
		return -1;

	if (user_rx)
		*user_rx = sess->user_rx_frames;

	return read_kernel_stats(sess, rx, redirected, pass);
}

void xdp_cap_close(xdp_cap_session *sess)
{
	if (!sess)
		return;

	if (sess->ifindex)
		(void)bpf_xdp_detach(sess->ifindex, sess->xdp_flags, NULL);
	if (sess->xsk)
		xsk_socket__delete(sess->xsk);
	if (sess->umem)
		xsk_umem__delete(sess->umem);
	if (sess->bpf_obj)
		bpf_object__close(sess->bpf_obj);
	if (sess->umem_area && sess->umem_area != MAP_FAILED)
		munmap(sess->umem_area, sess->umem_size);
	free(sess);
}

const char *xdp_cap_version(void)
{
	return "1.0.0";
}
