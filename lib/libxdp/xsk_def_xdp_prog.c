/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#define DEFAULT_QUEUE_IDS 64

struct {
        __uint(type, BPF_MAP_TYPE_XSKMAP);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct {
        __uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_def_prog);

SEC("xdp/xsk_def_prog")
int xsk_def_prog(struct xdp_md *ctx)
{
	int ret, index = ctx->rx_queue_index;

	/* A set entry here means that the corresponding queue_id
	 * has an active AF_XDP socket bound to it.
	 */
	ret = bpf_redirect_map(&xsks_map, index, XDP_PASS);
	if (ret > 0)
		return ret;

	/* Fallback for pre-5.3 kernels, not supporting default
	 * action in the flags parameter.
	 */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
