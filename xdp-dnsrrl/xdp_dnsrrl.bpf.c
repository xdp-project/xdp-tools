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

#ifdef  DEBUG
#define DEBUG_PRINTK(...) bpf_printk(__VA_ARGS__)
#else
#define DEBUG_PRINTK(...)
#endif

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
//#include "bpf/builtins.h"
#include "siphash4bpf.c"
#include "xdp_dnsrrl.h"

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
#define memcpy __builtin_memcpy

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

static volatile unsigned int ratelimit = 10;
static volatile unsigned int numcpus = 2;

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
} exclude_v4_prefixes __section(".maps");

struct ipv6_key {
	struct   bpf_lpm_trie_key lpm_key;
	__u64 ipv6;
} __attribute__((packed));

struct {
	__uint(type,  BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv6_key);
	__type(value, __u64);
	__uint(max_entries, 10000);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} exclude_v6_prefixes __section(".maps");

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
} state_map __section(".maps");

struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,   sizeof(struct in6_addr));
	__type(value, struct bucket_time);
	__uint(max_entries, RRL_SIZE);
} state_map_v6 __section(".maps");


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
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)
PARSE_FUNC_DECLARATION(dns_qrr)
PARSE_FUNC_DECLARATION(dns_rr)
PARSE_FUNC_DECLARATION(option)

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

static  inline
__u8 *skip_dname(struct cursor *c)
{
        __u8 *dname = c->pos;
	__u8 i;

        for (i = 0; i < 128; i++) { /* Maximum 128 labels */
                __u8 o;

                if (c->pos + 1 > c->end)
                        return 0;

                o = *(__u8 *)c->pos;
                if ((o & 0xC0) == 0xC0) {
                        /* Compression label is last label of dname. */
                        c->pos += 2;
                        return dname;

                } else if (o > 63 || c->pos + o + 1 > c->end)
                        /* Unknown label type */
                        return 0;

                c->pos += o + 1;
                if (!o)
                        return dname;
        }
        return 0;
}

static __always_inline enum xdp_action
do_rate_limit(struct udphdr *udp, struct dnshdr *dns, struct bucket_time *b)
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

	if (b->n_packets < ratelimit / numcpus)
		return XDP_PASS;

#if  RRL_SLIP == 0
	return XDP_DROP;
#else
# if RRL_SLIP >  1
	if (b->n_packets % RRL_SLIP)
		return XDP_DROP;
# endif
	//save the old header values
	__u16 old_val = dns->flags.as_value;

	// change the DNS flags
	dns->flags.as_bits_and_pieces.ad = 0;
	dns->flags.as_bits_and_pieces.qr = 1;
	dns->flags.as_bits_and_pieces.tc = 1;

	// change the UDP destination to the source
	udp->dest   = udp->source;
	udp->source = __bpf_htons(DNS_PORT);

	// calculate and write the new checksum
	update_checksum(&udp->check, old_val, dns->flags.as_value);

	// bounce
	return XDP_TX;
#endif
}

SEC("xdp")
int xdp_do_rate_limit_ipv6(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ipv6hdr   *ipv6;
	struct in6_addr   ipv6_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	DEBUG_PRINTK("xdp_do_rate_limit_ipv6\n");

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv6 = parse_ipv6hdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c)))
		return XDP_ABORTED;

	ipv6_addr = ipv6->saddr;
 	// get the rrl bucket from the map by IPv6 address
#if     RRL_IPv6_PREFIX_LEN == 128
#elif   RRL_IPv6_PREFIX_LEN >   96
	ipv6_addr.in6_u.u6_addr32[3] &= RRL_IPv6_MASK;
#else
	ipv6_addr.in6_u.u6_addr32[3] = 0;
# if    RRL_IPv6_PREFIX_LEN ==  96
# elif  RRL_IPv6_PREFIX_LEN >   64
	ipv6_addr.in6_u.u6_addr32[2] &= RRL_IPv6_MASK;
# else
	ipv6_addr.in6_u.u6_addr32[2] = 0;
#  if   RRL_IPv6_PREFIX_LEN ==  64
#  elif RRL_IPv6_PREFIX_LEN >   32
	ipv6_addr.in6_u.u6_addr32[1] &= RRL_IPv6_MASK;
#  else
	ipv6_addr.in6_u.u6_addr32[1] = 0;
#   if  RRL_IPv6_PREFIX_LEN ==   0
	ipv6_addr.in6_u.u6_addr32[0] = 0;
#   elif RRL_IPv6_PREFIX_LEN <  32
	ipv6_addr.in6_u.u6_addr32[0] &= RRL_IPv6_MASK;
#   endif
#  endif
# endif
#endif
 	struct bucket_time *b = bpf_map_lookup_elem(&state_map_v6, &ipv6_addr);

 	// did we see this IPv6 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket_time new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map_v6, &ipv6_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

SEC("xdp")
int xdp_do_rate_limit_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	__u32          ipv4_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	DEBUG_PRINTK("xdp_do_rate_limit_ipv4\n");

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c)))
		return XDP_ABORTED;

	// get the rrl bucket from the map by IPv4 address
#if   RRL_IPv4_PREFIX_LEN == 32
#elif RRL_IPv4_PREFIX_LEN ==  0
	ipv4_addr = 0;
#else
	ipv4_addr = ipv4->saddr & RRL_IPv4_MASK;
#endif
	struct bucket_time *b = bpf_map_lookup_elem(&state_map, &ipv4_addr);

	// did we see this IPv4 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket_time new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map, &ipv4_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} jmp_rate_table SEC(".maps") = {
        .values = {
                [DO_RATE_LIMIT_IPV6] = (void *)&xdp_do_rate_limit_ipv6,
                [DO_RATE_LIMIT_IPV4] = (void *)&xdp_do_rate_limit_ipv4,
        },
};

static __always_inline
int cookie_verify_ipv6(struct cursor *c, struct ipv6hdr *ipv6)
{
	__u8  input[32];
	__u64 hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv6->saddr, 16);
	siphash_ipv6(input, (__u8 *)&hash);
	return hash == ((__u64 *)c->pos)[2];
}

SEC("xdp")
int xdp_cookie_verify_ipv6(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ipv6hdr   *ipv6;
	struct dns_rr    *opt_rr;
	__u16          rdata_len;
	__u8           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv6 = parse_ipv6hdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		__u16       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv6(&c, ipv6)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				DEBUG_PRINTK("IPv6 valid cookie\n");
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			DEBUG_PRINTK("IPv6 bad cookie\n");
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV6);
	return XDP_PASS;
}


static __always_inline
int cookie_verify_ipv4(struct cursor *c, struct iphdr *ipv4)
{
	__u8  input[20];
	__u64 hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv4->saddr, 4);
	siphash_ipv4(input, (__u8 *)&hash);
	return hash == ((__u64 *)c->pos)[2];
}

SEC("xdp")
int xdp_cookie_verify_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	struct dns_rr    *opt_rr;
	__u16          rdata_len;
	__u8           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		__u16       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv4(&c, ipv4)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				DEBUG_PRINTK("IPv4 valid cookie\n");
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			DEBUG_PRINTK("IPv4 bad cookie\n");
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV4);
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} jmp_cookie_table SEC(".maps") = {
        .values = {
                [COOKIE_VERIFY_IPv6] = (void *)&xdp_cookie_verify_ipv6,
                [COOKIE_VERIFY_IPv4] = (void *)&xdp_cookie_verify_ipv4,
        },
};

SEC("xdp")
int xdp_dns(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct cursor     c;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
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

	if (md->eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c)))
			return XDP_PASS; /* Not IPV6 */
		switch (ipv6->nexthdr) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c))
			|| !(udp->dest == __bpf_htons(DNS_PORT))
			|| !(dns = parse_dnshdr(&c)))
				return XDP_PASS; /* Not DNS */
			// search for the prefix in the LPM trie
			struct {
				__u32        prefixlen;
				struct in6_addr ipv6_addr;
			} key6 = {
				.prefixlen = 64,
				.ipv6_addr = ipv6->daddr
			};
			// if the prefix matches, we exclude it from rate limiting
			if ((count=bpf_map_lookup_elem(&exclude_v6_prefixes, &key6))) {
				lock_xadd(count, 1);
				return XDP_PASS;
			}
			if (dns->flags.as_bits_and_pieces.qr
			||  dns->qdcount != __bpf_htons(1)
			||  dns->ancount || dns->nscount
			||  dns->arcount >  __bpf_htons(2)
			||  !skip_dname(&c)
			||  !parse_dns_qrr(&c))
				return XDP_ABORTED; // Return FORMERR?

			if (dns->arcount == 0) {
				bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV6);
				return XDP_PASS;
			}
			if (c.pos + 1 > c.end
			||  *(__u8 *)c.pos != 0)
				return XDP_ABORTED; // Return FORMERR?

			md->opt_pos = c.pos + 1 - (void *)(ipv6 + 1);
			bpf_tail_call(ctx, &jmp_cookie_table, COOKIE_VERIFY_IPv6);

			break;
		}
	} else if (md->eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c)))
			return XDP_PASS; /* Not IPv4 */
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c))
			|| !(udp->dest == __bpf_htons(DNS_PORT))
			|| !(dns = parse_dnshdr(&c)))
				return XDP_PASS; /* Not DNS */
			// search for the prefix in the LPM trie
			struct {
				__u32 prefixlen;
				__u32 ipv4_addr;
			} key4 = {
				.prefixlen = 32,
				.ipv4_addr = ipv4->saddr
			};

			// if the prefix matches, we exclude it from rate limiting
			if ((count=bpf_map_lookup_elem(&exclude_v4_prefixes, &key4))) {
				lock_xadd(count, 1);
				return XDP_PASS;
			}

			if (dns->flags.as_bits_and_pieces.qr
			||  dns->qdcount != __bpf_htons(1)
			||  dns->ancount || dns->nscount
			||  dns->arcount >  __bpf_htons(2)
			||  !skip_dname(&c)
			||  !parse_dns_qrr(&c))
				return XDP_ABORTED; // return FORMERR?

			if (dns->arcount == 0) {
				bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV4);
				return XDP_PASS;
			}
			if (c.pos + 1 > c.end
			||  *(__u8 *)c.pos != 0)
				return XDP_ABORTED; // Return FORMERR?

			md->opt_pos = c.pos + 1 - (void *)(ipv4 + 1);
			bpf_tail_call(ctx, &jmp_cookie_table, COOKIE_VERIFY_IPv4);

			break;
		}

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
