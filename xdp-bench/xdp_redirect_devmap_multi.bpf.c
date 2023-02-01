// SPDX-License-Identifier: GPL-2.0
#include <bpf/vmlinux.h>
#include <xdp/xdp_sample_shared.h>
#include <xdp/xdp_sample.bpf.h>
#include <xdp/xdp_sample_common.bpf.h>
#include <xdp/parsing_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 32);
} forward_map_general SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct bpf_devmap_val));
	__uint(max_entries, 32);
} forward_map_native SEC(".maps");

/* map to store egress interfaces mac addresses */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __be64);
	__uint(max_entries, 32);
} mac_map SEC(".maps");

static int xdp_redirect_devmap_multi(struct xdp_md *ctx, void *forward_map)
{
	__u32 key = bpf_get_smp_processor_id();
	struct datarec *rec;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	NO_TEAR_INC(rec->processed);

	return bpf_redirect_map(forward_map, 0,
				BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

SEC("xdp")
int redir_multi_general(struct xdp_md *ctx)
{
	return xdp_redirect_devmap_multi(ctx, &forward_map_general);
}

SEC("xdp")
int redir_multi_native(struct xdp_md *ctx)
{
	return xdp_redirect_devmap_multi(ctx, &forward_map_native);
}

SEC("xdp/devmap")
int xdp_devmap_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = ctx->egress_ifindex;
	struct ethhdr *eth = data;
	__be64 *mac;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	mac = bpf_map_lookup_elem(&mac_map, &key);
	if (mac)
		__builtin_memcpy(eth->h_source, mac, ETH_ALEN);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
