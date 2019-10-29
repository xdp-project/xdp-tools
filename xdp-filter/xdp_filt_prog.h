/* SPDX-License-Identifier: GPL-2.0 */

/* XDP filter program fragment. This header file contains the full-featured
 * program, split up with ifdefs. The actual program file in xdp_filt_kern.c
 * includes this file multiple times with different #defines to create the
 * different eBPF program sections that include only the needed features.
 */


#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "bpf/xdp_stats_kern_user.h"
#include "bpf/xdp_stats_kern.h"

#define CHECK_RET(ret) do {						\
		if ((ret) < 0) {					\
			action = XDP_ABORTED;				\
			goto out;					\
		}							\
	} while(0)

#define CHECK_VERDICT(type, param)					\
	do {								\
		if ((action = lookup_verdict_##type(param)) != XDP_PASS) \
			goto out;					\
	} while (0)

#define SRC_MASK (1<<0)
#define DST_MASK (1<<1)
#define TCP_MASK (1<<2)
#define UDP_MASK (1<<3)

#define CHECK_MAP(map, key, mask) do {				\
	value = bpf_map_lookup_elem(map, key);			\
	if ((value) && (*(value) & (mask)) == (mask))		\
		return XDP_DROP;				\
	} while(0)

#if defined(FILT_MODE_TCP) || defined(FILT_MODE_UDP)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u32);
} filter_ports SEC(".maps");

#ifdef FILT_MODE_TCP
static int __always_inline lookup_verdict_tcp(struct tcphdr *tcphdr)
{
	__u32 *value;

	CHECK_MAP(&filter_ports, &tcphdr->dest, DST_MASK | TCP_MASK);
	CHECK_MAP(&filter_ports, &tcphdr->source, SRC_MASK | TCP_MASK);
	return XDP_PASS;
}
#endif

#ifdef FILT_MODE_UDP
static int __always_inline lookup_verdict_udp(struct udphdr *udphdr)
{
	__u32 *value;

	CHECK_MAP(&filter_ports, &udphdr->dest, DST_MASK | UDP_MASK);
	CHECK_MAP(&filter_ports, &udphdr->source, SRC_MASK | UDP_MASK);
	return XDP_PASS;
}
#endif

#endif /* TCP || UDP */

#ifdef FILT_MODE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u32);
} filter_ipv4 SEC(".maps");

static int __always_inline lookup_verdict_ipv4(struct iphdr *iphdr)
{
	__u32 *value;

	CHECK_MAP(&filter_ipv4, &iphdr->daddr, DST_MASK);
	CHECK_MAP(&filter_ipv4, &iphdr->saddr, SRC_MASK);
	return XDP_PASS;
}

#define CHECK_VERDICT_IPV4(param) CHECK_VERDICT(ipv4, param)
#else
#define CHECK_VERDICT_IPV4(param)
#endif /* FILT_MODE_IPV4 */

#ifdef FILT_MODE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct in6_addr);
	__type(value, __u32);
} filter_ipv6 SEC(".maps");

static int __always_inline lookup_verdict_ipv6(struct ipv6hdr *ipv6hdr)
{
	__u32 *value;

	CHECK_MAP(&filter_ipv6, &ipv6hdr->daddr, DST_MASK);
	CHECK_MAP(&filter_ipv6, &ipv6hdr->saddr, SRC_MASK);
	return XDP_PASS;
}

#define CHECK_VERDICT_IPV6(param) CHECK_VERDICT(ipv6, param)
#else
#define CHECK_VERDICT_IPV6(param)
#endif /* FILT_MODE_IPV6 */

#ifdef FILT_MODE_ETHERNET
struct ethaddr {
	__u8 addr[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ethaddr);
	__type(value, __u32);
} filter_ethernet SEC(".maps");

static int __always_inline lookup_verdict_ethernet(struct ethhdr *eth)
{
	__u32 *value;

	CHECK_MAP(&filter_ethernet, eth->h_dest, DST_MASK);
	CHECK_MAP(&filter_ethernet, eth->h_source, SRC_MASK);
	return XDP_PASS;
}

#define CHECK_VERDICT_ETHERNET(param) CHECK_VERDICT(ethernet, param)
#else
#define CHECK_VERDICT_ETHERNET(param)
#endif /* FILT_MODE_ETHERNET */




SEC("xdp_filter")
int xdp_filter_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 action = XDP_PASS; /* Default action */
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;

	nh.pos = data;
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	CHECK_RET(eth_type);
	CHECK_VERDICT_ETHERNET(eth);

#if defined(FILT_MODE_IPV4) || defined(FILT_MODE_IPV6) || defined(FILT_MODE_TCP) || defined(FILT_MODE_UDP)
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	int ip_type;
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		CHECK_RET(ip_type);

		CHECK_VERDICT_IPV4(iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		CHECK_RET(ip_type);

		CHECK_VERDICT_IPV6(ipv6hdr);
	} else {
		goto out;
	}

#ifdef FILT_MODE_UDP
	struct udphdr *udphdr;
	if (ip_type == IPPROTO_UDP) {
		CHECK_RET(parse_udphdr(&nh, data_end, &udphdr));
		CHECK_VERDICT(udp, udphdr);
	}
#endif /* FILT_MODE_UDP */

#ifdef FILT_MODE_TCP
	struct tcphdr *tcphdr;
	if (ip_type == IPPROTO_TCP) {
		CHECK_RET(parse_tcphdr(&nh, data_end, &tcphdr));
		CHECK_VERDICT(tcp, tcphdr);
	}
#endif /* FILT_MODE_TCP*/
#endif /* FILT_MODE_{IPV4,IPV6,TCP,UDP} */
out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
