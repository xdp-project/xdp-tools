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
#include <xdp/xdp_sample_shared.h>
#include <xdp/xdp_sample.bpf.h>
#include <xdp/xdp_sample_common.bpf.h>
#include <xdp/parsing_helpers.h>

#include "xdp_basic.shared.h"

const volatile enum basic_program_mode prog_mode = BASIC_NO_TOUCH;
const volatile bool rxq_stats = 0;
const volatile enum xdp_action action = XDP_DROP;

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

SEC("xdp")
int xdp_basic_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = bpf_get_smp_processor_id();
	struct datarec *rec, *rxq_rec;
	struct ethhdr *eth = data;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	NO_TEAR_INC(rec->processed);

	if (rxq_stats) {
		key = ctx->rx_queue_index;
		rxq_rec = bpf_map_lookup_elem(&rxq_cnt, &key);
		if (!rxq_rec)
			return XDP_PASS;
		NO_TEAR_INC(rxq_rec->processed);
	}

	switch (prog_mode) {
	case BASIC_READ_DATA:
		if (bpf_ntohs(eth->h_proto) < ETH_P_802_3_MIN)
			return XDP_ABORTED;
		break;
	case BASIC_PARSE_IPHDR:
		if (parse_ip_header(ctx))
			return XDP_ABORTED;
		break;
	case BASIC_SWAP_MACS:
		swap_src_dst_mac(data);
		break;
	case BASIC_NO_TOUCH:
	default:
		break;
	}

	if (action == XDP_DROP) {
		NO_TEAR_INC(rec->dropped);
		if (rxq_stats)
			NO_TEAR_INC(rxq_rec->dropped);
	}

	return action;
}

char _license[] SEC("license") = "GPL";
