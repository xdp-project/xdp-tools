// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "vmlinux_local.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/errno.h>

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 2); // Index 0: TCP, Index 1: UDP
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} ddos_progs SEC(".maps");

// Main XDP program
SEC("xdp")
int xdp_ddos(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check packet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 key;

    switch (ip->protocol)  {
       case IPPROTO_TCP:
            key = 0; // Index for TCP DDoS program
            break;
        case IPPROTO_UDP:
            key = 1; // Index for UDP DDoS program
            break;
        default:
            return XDP_PASS;
    }

    // Attempt tail call (fails silently if no program is loaded)
    bpf_tail_call(ctx, &ddos_progs, key);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
