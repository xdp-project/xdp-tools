// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2024, BPFire. All rights reserved. */

#include "vmlinux_local.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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

#include "bpf/compiler.h"

#define XML_HEADER "<?xml"
#define XML_HEADER_LEN 5
#define MATCH_BYTES_LEN 4
#define RATE_LIMIT_THRESHOLD 10
#define RESET_INTERVAL_NS 1000000000 // 1 second in nanoseconds

#define PORT_START 10401
#define PORT_END   10413

// Map to store packet count and reset time for rate limiting
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} rate_limit_state SEC(".maps");

// Byte sequence to match
static const __u8 match_bytes[MATCH_BYTES_LEN] = { 0xff, 0x39, 0xe6, 0x87 };

// Helper to check if a port is within the specified range
static inline __u8 is_port_in_range(__u16 port) {
    return port >= PORT_START && port <= PORT_END;
}

SEC("xdp")
int udp_ddos(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS; // Not IPv4

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS; // Not UDP

    // Parse UDP header
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = __bpf_ntohs(udp->dest);
    if (!is_port_in_range(dest_port))
        return XDP_PASS; // Port not in range

    // Get UDP payload
    void *udp_payload = (void *)(udp + 1);
    if (udp_payload + MATCH_BYTES_LEN > data_end)
        return XDP_PASS; // Payload too small

    // Ensure payload is large enough for XML_HEADER_LEN
    if (udp_payload + XML_HEADER_LEN > data_end)
    	return XDP_PASS;
    // Check for XML header
    if (__builtin_memcmp(udp_payload, XML_HEADER, XML_HEADER_LEN) == 0) {
        // Rate limit logic for packets with XML header
        __u32 count_key = 0;
        __u32 reset_key = 1;
        __u64 *packet_count = bpf_map_lookup_elem(&rate_limit_state, &count_key);
        __u64 *last_reset_time = bpf_map_lookup_elem(&rate_limit_state, &reset_key);
        __u64 now = bpf_ktime_get_ns();

        // Initialize map entries if not present
        if (!packet_count || !last_reset_time) {
            __u64 initial_count = 1;
            bpf_map_update_elem(&rate_limit_state, &count_key, &initial_count, BPF_ANY);
            bpf_map_update_elem(&rate_limit_state, &reset_key, &now, BPF_ANY);
            return XDP_PASS;
        }

        // Reset packet count if interval elapsed
        if ((now - *last_reset_time) >= RESET_INTERVAL_NS) {
            *packet_count = 0;
            *last_reset_time = now;
            bpf_map_update_elem(&rate_limit_state, &count_key, packet_count, BPF_ANY);
            bpf_map_update_elem(&rate_limit_state, &reset_key, last_reset_time, BPF_ANY);
        }

        // Enforce rate limit
        if (*packet_count >= RATE_LIMIT_THRESHOLD) {
            bpf_printk("Rate limit exceeded for XML header on port %u\n", dest_port);
            return XDP_PASS; // Drop packets exceeding the limit
        }

        // Increment the packet count and update map
        (*packet_count)++;
        bpf_map_update_elem(&rate_limit_state, &count_key, packet_count, BPF_ANY);

        return XDP_PASS;
    }

    // Check for 4-byte payload match
    if (__builtin_memcmp(udp_payload, match_bytes, MATCH_BYTES_LEN) != 0) {
        bpf_printk("Dropped packet with mismatched payload on port %u\n", dest_port);
        return XDP_DROP; // Drop packets with mismatched payload
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

