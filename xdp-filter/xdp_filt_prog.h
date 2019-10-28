/* SPDX-License-Identifier: GPL-2.0 */

/* XDP filter program fragment. This header file contains the full-featured
 * program, split up with ifdefs. The actual program file in xdp_filt_kern.c
 * includes this file multiple times with different #defines to create the
 * different eBPF program sections that include only the needed features.
 */


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

#undef CHECK_VERDICT_ETHERNET
#ifdef FILT_MODE_ETHERNET
#define CHECK_VERDICT_ETHERNET(param) CHECK_VERDICT(ethernet, param)
#else
#define CHECK_VERDICT_ETHERNET(param)
#endif

#undef CHECK_VERDICT_IPV4
#ifdef FILT_MODE_IPV4
#define CHECK_VERDICT_IPV4(param) CHECK_VERDICT(ipv4, param)
#else
#define CHECK_VERDICT_IPV4(param)
#endif

#undef CHECK_VERDICT_IPV6
#ifdef FILT_MODE_IPV6
#define CHECK_VERDICT_IPV6(param) CHECK_VERDICT(ipv6, param)
#else
#define CHECK_VERDICT_IPV6(param)
#endif

int FUNC_NAME (struct xdp_md *ctx)
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
