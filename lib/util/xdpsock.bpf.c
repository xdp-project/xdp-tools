// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* This XDP program is only needed for multi-buffer and XDP_SHARED_UMEM modes.
 * If you do not use these modes, libxdp can supply an XDP program for you.
 */

#define MAX_SOCKS 4
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

int num_socks = 0;
static unsigned int rr;

SEC("xdp.frags")
int xdp_sock_prog(struct xdp_md *ctx)
{
	rr = (rr + 1) & (num_socks - 1);
	return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}
