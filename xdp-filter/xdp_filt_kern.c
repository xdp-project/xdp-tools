/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "bpf/xdp_stats_kern_user.h"
#include "bpf/xdp_stats_kern.h"

int lookup_verdict_ethernet(struct ethhdr *eth)
{
	return XDP_PASS;
}

int lookup_verdict_ipv4(struct iphdr *iphdr)
{
	return XDP_PASS;
}

int lookup_verdict_ipv6(struct ipv6hdr *ipv6hdr)
{
	return XDP_PASS;
}

int lookup_verdict_tcp(struct tcphdr *tcphdr)
{
	return XDP_PASS;
}

int lookup_verdict_udp(struct udphdr *udphdr)
{
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
