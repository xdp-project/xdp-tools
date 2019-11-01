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

#include "common_kern_user.h"

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

#define CHECK_MAP(map, key, mask) do {					\
		__u64 *value;						\
		value = bpf_map_lookup_elem(map, key);			\
		if ((value) && (*(value) & (mask)) == (mask)) {	\
			*value += (1 << COUNTER_SHIFT);		\
			return XDP_DROP;				\
		}							\
	} while(0)

#if defined(FILT_MODE_TCP) || defined(FILT_MODE_UDP)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_PORTS SEC(".maps");

#ifdef FILT_MODE_TCP
static int __always_inline lookup_verdict_tcp(struct tcphdr *tcphdr)
{
	CHECK_MAP(&filter_ports, &tcphdr->dest, MAP_FLAG_DST | MAP_FLAG_TCP);
	CHECK_MAP(&filter_ports, &tcphdr->source, MAP_FLAG_SRC | MAP_FLAG_TCP);
	return XDP_PASS;
}
#define FEATURE_TCP FEAT_TCP
#else
#define FEATURE_TCP 0
#endif

#ifdef FILT_MODE_UDP
static int __always_inline lookup_verdict_udp(struct udphdr *udphdr)
{
	CHECK_MAP(&filter_ports, &udphdr->dest, MAP_FLAG_DST | MAP_FLAG_UDP);
	CHECK_MAP(&filter_ports, &udphdr->source, MAP_FLAG_SRC | MAP_FLAG_UDP);
	return XDP_PASS;
}
#define FEATURE_UDP FEAT_UDP
#else
#define FEATURE_UDP 0
#endif

#else
#define FEATURE_UDP 0
#define FEATURE_TCP 0
#endif /* TCP || UDP */

#ifdef FILT_MODE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10000);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_IPV4 SEC(".maps");

static int __always_inline lookup_verdict_ipv4(struct iphdr *iphdr)
{
	CHECK_MAP(&filter_ipv4, &iphdr->daddr, MAP_FLAG_DST);
	CHECK_MAP(&filter_ipv4, &iphdr->saddr, MAP_FLAG_SRC);
	return XDP_PASS;
}

#define CHECK_VERDICT_IPV4(param) CHECK_VERDICT(ipv4, param)
#define FEATURE_IPV4 FEAT_IPV4
#else
#define FEATURE_IPV4 0
#define CHECK_VERDICT_IPV4(param)
#endif /* FILT_MODE_IPV4 */

#ifdef FILT_MODE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct in6_addr);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_IPV6 SEC(".maps");

static int __always_inline lookup_verdict_ipv6(struct ipv6hdr *ipv6hdr)
{
	CHECK_MAP(&filter_ipv6, &ipv6hdr->daddr, MAP_FLAG_DST);
	CHECK_MAP(&filter_ipv6, &ipv6hdr->saddr, MAP_FLAG_SRC);
	return XDP_PASS;
}

#define CHECK_VERDICT_IPV6(param) CHECK_VERDICT(ipv6, param)
#define FEATURE_IPV6 FEAT_IPV6
#else
#define FEATURE_IPV6 0
#define CHECK_VERDICT_IPV6(param)
#endif /* FILT_MODE_IPV6 */

#ifdef FILT_MODE_ETHERNET
struct ethaddr {
	__u8 addr[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct ethaddr);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_ETHERNET SEC(".maps");

static int __always_inline lookup_verdict_ethernet(struct ethhdr *eth)
{
	CHECK_MAP(&filter_ethernet, eth->h_dest, MAP_FLAG_DST);
	CHECK_MAP(&filter_ethernet, eth->h_source, MAP_FLAG_SRC);
	return XDP_PASS;
}

#define CHECK_VERDICT_ETHERNET(param) CHECK_VERDICT(ethernet, param)
#define FEATURE_ETHERNET FEAT_ETHERNET
#else
#define FEATURE_ETHERNET 0
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
__u32 _features SEC("features") = (FEATURE_ETHERNET | FEATURE_IPV4 | FEATURE_IPV6 | FEATURE_UDP | FEATURE_TCP);
