#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern int filterc_test_prog(struct xdp_md *ctx);

SEC("xdp")
int wrapper_prog(struct xdp_md *ctx)
{
	return filterc_test_prog(ctx);
}

char _license[] SEC("license") = "GPL";
