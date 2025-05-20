#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_adjust_tail(struct xdp_md *ctx)
{
	if (bpf_xdp_adjust_tail(ctx, -1) < 0)
		return XDP_ABORTED;
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
