#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

struct {
	__uint(priority, 10);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_pass);

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
