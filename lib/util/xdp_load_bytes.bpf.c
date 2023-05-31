// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef HAVE_LIBBPF_BPF_PROGRAM__TYPE
static long (*bpf_xdp_load_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 189;
#endif

SEC("xdp")
int xdp_probe_prog(struct xdp_md *ctx)
{
	__u8 buf[10];
	int err;

	err = bpf_xdp_load_bytes(ctx, 0, buf, sizeof(buf));
	if (err)
		return XDP_ABORTED;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
