/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <bpf/vmlinux.h>
#include <xdp/xdp_sample_shared.h>
#include <xdp/xdp_sample.bpf.h>
#include <xdp/xdp_sample_common.bpf.h>
#include <xdp/parsing_helpers.h>

/* The 2nd xdp prog on egress does not support skb mode, so we define two
 * maps, tx_port_general and tx_port_native.
 */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1);
} tx_port_general SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct bpf_devmap_val));
	__uint(max_entries, 1);
} tx_port_native SEC(".maps");

/* store egress interface mac address */
const volatile char tx_mac_addr[ETH_ALEN];

static __always_inline int xdp_redirect_devmap(struct xdp_md *ctx, void *redirect_map)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = bpf_get_smp_processor_id();
	struct ethhdr *eth = data;
	struct datarec *rec;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	NO_TEAR_INC(rec->processed);
	swap_src_dst_mac(data);
	return bpf_redirect_map(redirect_map, 0, 0);
}

SEC("xdp")
int redir_devmap_general(struct xdp_md *ctx)
{
	return xdp_redirect_devmap(ctx, &tx_port_general);
}

SEC("xdp")
int redir_devmap_native(struct xdp_md *ctx)
{
	return xdp_redirect_devmap(ctx, &tx_port_native);
}

SEC("xdp/devmap")
int xdp_redirect_devmap_egress(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_source, (const char *)tx_mac_addr, ETH_ALEN);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
