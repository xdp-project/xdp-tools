/*
 * Copyright (c) 2024, BPFire.  All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "vmlinux_local.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 saddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} geoip_map SEC(".maps");

SEC("xdp")
int xdp_geoip(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .saddr = iph->saddr,
    };

    __u8 *action = bpf_map_lookup_elem(&geoip_map, &key);
    if (action && *action == 1) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

