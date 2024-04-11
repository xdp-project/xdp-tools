/*
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
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
#include "xdp_udp.h"

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
#define memcpy __builtin_memcpy
#define MAX_ALLOWED_PORTS 8
#define NTP_PORT 123
#define DNS_PORT 53

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

static volatile unsigned int ratelimit = 1000;

struct ipv4_key {
	struct   bpf_lpm_trie_key lpm_key;
	__u8  ipv4[4];
};

struct {
	__uint(type,  BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv4_key);
	__type(value, __u64);
	__uint(max_entries, 10000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} udp_exclude_v4_prefixes __section(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u16);
        __uint(max_entries, MAX_ALLOWED_PORTS);
} udp_ports SEC(".maps");


/*
 *  Store the time frame
 */
struct bucket_time {
	__u64 start_time;
	__u64 n_packets;
};

struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,   __u32);
	__type(value, struct bucket_time);
	__uint(max_entries, RRL_SIZE);
} udp_state_map __section(".maps");

/** Copied from the kernel module of the base03-map-counter example of the
 ** XDP Hands-On Tutorial (see https://github.com/xdp-project/xdp-tutorial )
 *
 * LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/*
 *  Store the VLAN header
 */
struct vlanhdr {
	__u16 tci;
	__u16 encap_proto;
};

/*
 *  Helper pointer to parse the incoming packets
 */
struct cursor {
	void *pos;
	void *end;
};

static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline \
struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							\
	struct STRUCT *ret = c->pos;			\
	if (c->pos + sizeof(struct STRUCT) > c->end)	\
		return 0;				\
	c->pos += sizeof(struct STRUCT);		\
	return ret;					\
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(udphdr)

static __always_inline
struct ethhdr *parse_eth(struct cursor *c, __u16 *eth_proto)
{
	struct ethhdr  *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;

	*eth_proto = eth->h_proto;
	if (*eth_proto == __bpf_htons(ETH_P_8021Q)
	||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == __bpf_htons(ETH_P_8021Q)
		||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

static __always_inline enum xdp_action
do_rate_limit(struct udphdr *udp, struct bucket_time *b)
{
	// increment number of packets
	b->n_packets++;

	// get the current and elapsed time
	__u64 now = bpf_ktime_get_ns();
	__u64 elapsed = now - b->start_time;

	// make sure the elapsed time is set and not outside of the frame
	if (b->start_time == 0 || elapsed >= FRAME_SIZE)
	{
		// start new time frame
		b->start_time = now;
		b->n_packets = 0;
	}

	if (b->n_packets < ratelimit)
		return XDP_PASS;

	return XDP_DROP;
}

static __always_inline bool check_port_allowed(__u16 port)
{
        __u32 i;

        for (i = 0; i < MAX_ALLOWED_PORTS; i++) {
                __u32 key = i;
                __u16 *value;

                value = bpf_map_lookup_elem(&udp_ports, &key);

                if (!value)
                        break;
                /* 0 is a terminator value. Check it first to avoid matching on
                 * a forbidden port == 0 and returning true.
                 */
                if (*value == 0)
                        break;

                if (*value == port)
                        return true;
        }

        return false;
}

SEC("xdp")
int udp_do_rate_limit_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	__u32          ipv4_addr;
	struct udphdr    *udp;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)))
		 return XDP_ABORTED;

	// get the rrl bucket from the map by IPv4 address
#if   RRL_IPv4_PREFIX_LEN == 32
#elif RRL_IPv4_PREFIX_LEN ==  0
	ipv4_addr = 0;
#else
	ipv4_addr = ipv4->saddr & RRL_IPv4_MASK;
#endif
	struct bucket_time *b = bpf_map_lookup_elem(&udp_state_map, &ipv4_addr);

	// did we see this IPv4 address before?
	if (b)
		return do_rate_limit(udp, b);

	// create new starting bucket for this key
	struct bucket_time new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&udp_state_map, &ipv4_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} udp_rate_table SEC(".maps") = {
        .values = {
                [UDP_RATE_LIMIT_IPV4] = (void *)&udp_do_rate_limit_ipv4,
        },
};

SEC("xdp")
int xdp_udp(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct cursor     c;
	struct ethhdr    *eth;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	__u64         *count;

	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
		return XDP_PASS;

	cursor_init(&c, ctx);
	md = (void *)(long)ctx->data_meta;
	if ((void *)(md + 1) > c.pos)
		return XDP_PASS;

	if (!(eth = parse_eth(&c, &md->eth_proto)))
		return XDP_PASS;
	md->ip_pos = c.pos - (void *)eth;

	if (md->eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c)))
			return XDP_PASS; /* Not IPv4 */
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c)))
				return XDP_DROP;
			// allow DNS or NTP response pass through, but still do rate limit
			if ((bpf_ntohs(udp->source == __bpf_htons(DNS_PORT))
			|| (bpf_ntohs(udp->source) == __bpf_htons(NTP_PORT))))
				goto do_rate;
			// drop UDP destination port not in allowed port
			if (!check_port_allowed(bpf_ntohs(udp->dest)))
				return XDP_DROP;
			// search for the prefix in the LPM trie
do_rate:
		{
			struct {
				__u32 prefixlen;
				__u32 ipv4_addr;
			} key4 = {
				.prefixlen = 32,
				.ipv4_addr = ipv4->saddr
			};

			// if the prefix matches, we exclude it from rate limiting
			if ((count=bpf_map_lookup_elem(&udp_exclude_v4_prefixes, &key4))) {
				lock_xadd(count, 1);
				return XDP_PASS;
			}

			bpf_tail_call(ctx, &udp_rate_table, UDP_RATE_LIMIT_IPV4);
			return XDP_PASS;
		}

			break;
		}

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
