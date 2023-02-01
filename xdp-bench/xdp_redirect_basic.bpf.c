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
#include <linux/if_ether.h>

const volatile int ifindex_out;

SEC("xdp")
int xdp_redirect_basic_prog(struct xdp_md *ctx)
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
	return bpf_redirect(ifindex_out, 0);
}

char _license[] SEC("license") = "GPL";
