// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
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
#include <linux/bpf.h>
#include <xdp/xdp_sample_shared.h>
#include <xdp/xdp_sample.bpf.h>
#include <xdp/xdp_sample_common.bpf.h>
#include <xdp/parsing_helpers.h>

#ifndef HAVE_LIBBPF_BPF_PROGRAM__TYPE
static long (*bpf_xdp_load_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 189;
static long (*bpf_xdp_store_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 190;
#endif

const volatile bool rxq_stats = 0;
const volatile enum xdp_action action = XDP_DROP;

static int parse_ip_header_load(struct xdp_md *ctx)
{
	int eth_type, ip_type, err, offset = 0;
	struct ipv6hdr ipv6hdr;
	struct iphdr iphdr;
	struct ethhdr eth;

	err = bpf_xdp_load_bytes(ctx, offset, &eth, sizeof(eth));
	if (err)
		return err;

	eth_type = eth.h_proto;
	offset = sizeof(eth);

	if (eth_type == bpf_htons(ETH_P_IP)) {
		err = bpf_xdp_load_bytes(ctx, offset, &iphdr, sizeof(iphdr));
		if (err)
			return err;

		ip_type = iphdr.protocol;
		if (ip_type < 0)
			return ip_type;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		err = bpf_xdp_load_bytes(ctx, offset, &ipv6hdr, sizeof(ipv6hdr));
		if (err)
			return err;

		ip_type = ipv6hdr.nexthdr;
		if (ip_type < 0)
			return ip_type;
	}

	return 0;
}

static int parse_ip_header(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	int eth_type, ip_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return eth_type;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0)
			return ip_type;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type < 0)
			return ip_type;
	}

	return 0;
}

static int record_stats(__u32 rxq_idx, bool success)
{
	__u32 key = bpf_get_smp_processor_id();
	struct datarec *rec;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return -1;

	NO_TEAR_INC(rec->processed);
	if (action == XDP_DROP && success)
		NO_TEAR_INC(rec->dropped);

	if (rxq_stats) {
		struct datarec *rxq_rec;

		rxq_rec = bpf_map_lookup_elem(&rxq_cnt, &rxq_idx);
		if (!rxq_rec)
			return -1;

		NO_TEAR_INC(rxq_rec->processed);

		if (action == XDP_DROP && success)
			NO_TEAR_INC(rxq_rec->dropped);
	}

	return 0;
}


SEC("xdp")
int xdp_basic_prog(struct xdp_md *ctx)
{
	if (record_stats(ctx->rx_queue_index, true))
		return XDP_ABORTED;

	return action;
}

SEC("xdp")
int xdp_read_data_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int ret = action;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_ABORTED;

	if (bpf_ntohs(eth->h_proto) < ETH_P_802_3_MIN)
		ret = XDP_ABORTED;

	if (record_stats(ctx->rx_queue_index, ret==action))
		return XDP_ABORTED;

	return ret;
}

SEC("xdp")
int xdp_read_data_load_bytes_prog(struct xdp_md *ctx)
{
	int err, offset = 0;
	struct ethhdr eth;
	int ret = action;

	err = bpf_xdp_load_bytes(ctx, offset, &eth, sizeof(eth));
	if (err)
		return err;

	if (bpf_ntohs(eth.h_proto) < ETH_P_802_3_MIN)
		ret = XDP_ABORTED;

	if (record_stats(ctx->rx_queue_index, ret==action))
		return XDP_ABORTED;

	return ret;
}

SEC("xdp")
int xdp_swap_macs_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_ABORTED;

	swap_src_dst_mac(data);

	if (record_stats(ctx->rx_queue_index, true))
		return XDP_ABORTED;

	return action;
}

SEC("xdp")
int xdp_swap_macs_load_bytes_prog(struct xdp_md *ctx)
{
	int err, offset = 0;
	struct ethhdr eth;

	err = bpf_xdp_load_bytes(ctx, offset, &eth, sizeof(eth));
	if (err)
		return err;

	swap_src_dst_mac(&eth);

	err = bpf_xdp_store_bytes(ctx, offset, &eth, sizeof(eth));
	if (err)
		return err;

	if (record_stats(ctx->rx_queue_index, true))
		return XDP_ABORTED;

	return action;
}

SEC("xdp")
int xdp_parse_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int ret = action;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_ABORTED;

	if (parse_ip_header(ctx))
		ret = XDP_ABORTED;

	if (record_stats(ctx->rx_queue_index, ret==action))
		return XDP_ABORTED;

	return ret;
}

SEC("xdp")
int xdp_parse_load_bytes_prog(struct xdp_md *ctx)
{
	int ret = action;

	if (parse_ip_header_load(ctx))
		ret = XDP_ABORTED;

	if (record_stats(ctx->rx_queue_index, ret==action))
		return XDP_ABORTED;

	return ret;
}

char _license[] SEC("license") = "GPL";
