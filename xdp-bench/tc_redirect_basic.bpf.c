// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Tariro Mukute
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <xdp/xdp_sample_common.bpf.h>

// Read-only global variable for the output interface index.
// This will be set by the userspace application before loading.
const volatile int ifindex_out;

static int record_stats()
{
	__u32 key = bpf_get_smp_processor_id();
	struct datarec *rec;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return -1;
	
	// Atomically increment the 'processed' counter for this CPU.
	NO_TEAR_INC(rec->processed);

	return 0;
}

SEC("tc/ingress")
int tc_redirect_prog(struct __sk_buff *skb)
{
    // Get pointers to the start and end of the packet data.
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

    // Boundary check: ensure the Ethernet header is within the packet.
	if (data + sizeof(*eth) > data_end)
		return TC_ACT_SHOT; // Drop packet if it's too small.

    if (record_stats())
		return TC_ACT_SHOT;

    // Redirect the packet to the specified output interface.
	return bpf_redirect(ifindex_out, 0);
}

SEC("tc/ingress")
int tc_swap_macs_redirect_prog(struct __sk_buff *skb)
{
    // Get pointers to the start and end of the packet data.
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

    // Boundary check: ensure the Ethernet header is within the packet.
	if (data + sizeof(*eth) > data_end)
		return TC_ACT_SHOT; // Drop packet if it's too small.

    if (record_stats())
		return TC_ACT_SHOT;

    // Swap the source and destination MAC addresses in the Ethernet header.
	swap_src_dst_mac(data);

    // Redirect the packet to the specified output interface.
	return bpf_redirect(ifindex_out, 0);
}

char _license[] SEC("license") = "GPL";