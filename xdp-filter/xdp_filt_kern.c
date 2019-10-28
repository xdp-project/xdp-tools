/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "bpf/xdp_stats_kern_user.h"
#include "bpf/xdp_stats_kern.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u32);
} filter_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u32);
} filter_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct in6_addr);
	__type(value, __u32);
} filter_ipv6 SEC(".maps");

struct ethaddr {
	__u8 addr[ETH_ALEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ethaddr);
	__type(value, __u32);
} filter_ethernet SEC(".maps");

#define SRC_MASK (1<<0)
#define DST_MASK (1<<1)
#define TCP_MASK (1<<2)
#define UDP_MASK (1<<3)

#define CHECK_MAP(map, key, mask) do {				\
	value = bpf_map_lookup_elem(map, key);			\
	if ((value) && (*(value) & (mask)) == (mask))		\
		return XDP_DROP;				\
	} while(0)

int lookup_verdict_ethernet(struct ethhdr *eth)
{
	struct ethaddr *addr;
	__u32 *value;

	addr = (void *)eth->h_dest;
	CHECK_MAP(&filter_ethernet, addr, DST_MASK);

	addr = (void *)eth->h_source;
	CHECK_MAP(&filter_ethernet, addr, SRC_MASK);

	return XDP_PASS;
}

int lookup_verdict_ipv4(struct iphdr *iphdr)
{
	__u32 *value;

	CHECK_MAP(&filter_ipv4, &iphdr->daddr, DST_MASK);
	CHECK_MAP(&filter_ipv4, &iphdr->saddr, SRC_MASK);

	return XDP_PASS;
}

int lookup_verdict_ipv6(struct ipv6hdr *ipv6hdr)
{
	return XDP_PASS;
}

int lookup_verdict_tcp(struct tcphdr *tcphdr)
{
	__u32 *value;
	CHECK_MAP(&filter_ports, &tcphdr->dest, DST_MASK | TCP_MASK);
	CHECK_MAP(&filter_ports, &tcphdr->source, SRC_MASK | TCP_MASK);
	return XDP_PASS;
}

int lookup_verdict_udp(struct udphdr *udphdr)
{
	__u32 *value;
	CHECK_MAP(&filter_ports, &udphdr->dest, DST_MASK | UDP_MASK);
	CHECK_MAP(&filter_ports, &udphdr->source, SRC_MASK | UDP_MASK);
	return XDP_PASS;
}

SEC("xdp_filter_ethernet")
#undef FUNC_NAME
#define FUNC_NAME xdp_filter_ethernet_func
#define FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#undef FILT_MODE_UDP
#undef FILT_MODE_TCP
#include "xdp_filt_prog.h"

SEC("xdp_filter_ip")
#undef FUNC_NAME
#define FUNC_NAME xdp_filter_ip_func
#undef FILT_MODE_ETHERNET
#define FILT_MODE_IPV4
#define FILT_MODE_IPV6
#undef FILT_MODE_UDP
#undef FILT_MODE_TCP
#include "xdp_filt_prog.h"

SEC("xdp_filter_tcp")
#undef FUNC_NAME
#define FUNC_NAME xdp_filter_tcp_func
#undef FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#undef FILT_MODE_UDP
#define FILT_MODE_TCP
#include "xdp_filt_prog.h"

SEC("xdp_filter_udp")
#undef FUNC_NAME
#define FUNC_NAME xdp_filter_udp_func
#undef FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#define FILT_MODE_UDP
#undef FILT_MODE_TCP
#include "xdp_filt_prog.h"

SEC("xdp_filter_all")
#undef FUNC_NAME
#define FUNC_NAME xdp_filter_all_func
#define FILT_MODE_ETHERNET
#define FILT_MODE_IPV4
#define FILT_MODE_IPV6
#define FILT_MODE_UDP
#define FILT_MODE_TCP
#include "xdp_filt_prog.h"

char _license[] SEC("license") = "GPL";
