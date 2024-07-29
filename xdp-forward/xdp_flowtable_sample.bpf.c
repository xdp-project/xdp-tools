// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <linux/netfilter.h>
#include <bpf/bpf_core_read.h>

#define AF_INET		2

struct bpf_flowtable_opts {
	__s32 error;
};

struct flow_offload_tuple_rhash *
bpf_xdp_flow_lookup(struct xdp_md *, struct bpf_fib_lookup *,
		    struct bpf_flowtable_opts *, __u32) __ksym;

SEC("xdp")
int xdp_fwd_flowtable_sample(struct xdp_md *ctx)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct bpf_flowtable_opts opts = {};
	struct bpf_fib_lookup tuple = {
		.family = AF_INET,
		.ifindex = ctx->ingress_ifindex,
	};

	tuplehash = bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts));
	if (!tuplehash)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
