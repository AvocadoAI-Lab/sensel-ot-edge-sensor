/* Track A: XDP redirect all matched traffic to AF_XDP socket (passive mirror). */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline int packet_matches(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
		return 0;

	struct ethhdr *eth = data;
	__u16 proto = bpf_ntohs(eth->h_proto);

	if (proto == 0x88B8)
		return 1;

	if (proto != ETH_P_IP)
		return 0;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return 0;

	struct iphdr *ip = (void *)(eth + 1);
	if (ip->protocol != IPPROTO_TCP)
		return 0;

	__u32 hdr_len = sizeof(struct ethhdr) + (__u32)ip->ihl * 4U;
	if (data + hdr_len + sizeof(struct tcphdr) > data_end)
		return 0;

	struct tcphdr *tcp = (void *)data + hdr_len;
	__u16 sport = bpf_ntohs(tcp->source);
	__u16 dport = bpf_ntohs(tcp->dest);

	return sport == 102 || dport == 102 || sport == 502 || dport == 502;
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
	if (!packet_matches(ctx))
		return XDP_PASS;

	__u32 q = ctx->rx_queue_index;
	return bpf_redirect_map(&xsks_map, q, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
