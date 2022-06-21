#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#define bpf_debug(fmt, ...)				\
	{						\
		char __fmt[] = fmt;			\
		bpf_trace_printk(__fmt, sizeof(__fmt),	\
				 ##__VA_ARGS__);	\
	}

SEC("xdp")
int xdp_test_prog_with_a_long_name(struct xdp_md *ctx)
{
	bpf_debug("PASS[1]: prog %u\n", ctx->ingress_ifindex);
	return XDP_PASS;
}

SEC("xdp")
int xdp_test_prog_with_a_long_name_too(struct xdp_md *ctx)
{
	bpf_debug("PASS[2]: prog %u\n", ctx->ingress_ifindex);
	return XDP_PASS;
}

struct {
	__uint(priority, 5);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_test_prog_with_a_long_name);

char _license[] SEC("license") = "GPL";
