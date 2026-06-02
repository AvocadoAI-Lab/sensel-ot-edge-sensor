#ifndef XDP_CAPTURE_H
#define XDP_CAPTURE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xdp_cap_session xdp_cap_session;

xdp_cap_session *xdp_cap_open(const char *ifname, int queue_id,
			      const char *bpf_obj_path, int xdp_mode,
			      int frame_size, int num_frames);

int xdp_cap_recv(xdp_cap_session *sess, unsigned char *buf, int buf_size,
		 int timeout_ms);

int xdp_cap_stats(xdp_cap_session *sess, uint64_t *rx, uint64_t *redirected,
		  uint64_t *pass, uint64_t *user_rx);

void xdp_cap_close(xdp_cap_session *sess);

const char *xdp_cap_last_error(void);

const char *xdp_cap_version(void);

#ifdef __cplusplus
}
#endif

#endif
