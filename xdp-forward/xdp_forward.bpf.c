// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <linux/netfilter.h>
#include <bpf/bpf_core_read.h>

#define AF_INET				2
#define AF_INET6			10

#define IPV6_FLOWINFO_MASK              bpf_htons(0x0FFFFFFF)

#define IP_MF				0x2000	/* "More Fragments" */
#define IP_OFFSET			0x1fff	/* "Fragment Offset" */
#define CSUM_MANGLED_0			((__sum16)0xffff)

#define BIT(x)				(1 << (x))

struct bpf_flowtable_opts {
	__s32 error;
};

struct flow_offload_tuple_rhash *
bpf_xdp_flow_lookup(struct xdp_md *, struct bpf_fib_lookup *,
		    struct bpf_flowtable_opts *, __u32) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32)iph->check;

	check += (__u32)bpf_htons(0x0100);
	iph->check = (__sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, __u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		return XDP_PASS;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	/*
	 * Some rc (return codes) from bpf_fib_lookup() are important,
	 * to understand how this XDP-prog interacts with network stack.
	 *
	 * BPF_FIB_LKUP_RET_NO_NEIGH:
	 *  Even if route lookup was a success, then the MAC-addresses are also
	 *  needed.  This is obtained from arp/neighbour table, but if table is
	 *  (still) empty then BPF_FIB_LKUP_RET_NO_NEIGH is returned.  To avoid
	 *  doing ARP lookup directly from XDP, then send packet to normal
	 *  network stack via XDP_PASS and expect it will do ARP resolution.
	 *
	 * BPF_FIB_LKUP_RET_FWD_DISABLED:
	 *  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
	 *  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
	 *  enabled this on ingress device.
	 */
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Verify egress index has been configured as TX-port.
		 * (Note: User can still have inserted an egress ifindex that
		 * doesn't support XDP xmit, which will result in packet drops).
		 *
		 * Note: lookup in devmap supported since 0cdbb4b09a0.
		 * If not supported will fail with:
		 *  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
		 */
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS;

		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return bpf_redirect_map(&xdp_tx_ports, fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

SEC("xdp")
int xdp_fwd_fib_full(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, 0);
}

SEC("xdp")
int xdp_fwd_fib_direct(struct xdp_md *ctx)
{
	return xdp_fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend)
{
	__u32 res = csum + addend;

	return res + (res < addend);
}

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~csum;
}

static __always_inline __u16 csum_replace4(__u32 csum, __u32 from, __u32 to)
{
	__u32 tmp = csum_add(~csum, ~from);

	return csum_fold(csum_add(tmp, to));
}

static __always_inline __u16 csum_replace16(__u32 csum, __u32 *from, __u32 *to)
{
	__u32 diff[] = {
		~from[0], ~from[1], ~from[2], ~from[3],
		to[0], to[1], to[2], to[3],
	};

	csum = bpf_csum_diff(0, 0, diff, sizeof(diff), ~csum);
	return csum_fold(csum);
}

static __always_inline int
xdp_flowtable_check_tcp_state(void *ports, void *data_end, __u8 proto)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcph = ports;

		if (tcph + 1 > data_end)
			return -1;

		if (tcph->fin || tcph->rst)
			return -1;
	}

	return 0;
}

static __always_inline void
xdp_flowtable_update_port_csum(struct flow_ports *ports, void *data_end,
			       __u8 proto, __be16 port, __be16 nat_port)
{
	switch (proto) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)ports;

		if (tcph + 1 > data_end)
			break;

		tcph->check = csum_replace4((__u32)tcph->check, (__u32)port,
					    (__u32)nat_port);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)ports;

		if (udph + 1 > data_end)
			break;

		if (!udph->check)
			break;

		udph->check = csum_replace4((__u32)udph->check, (__u32)port,
					    (__u32)nat_port);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	default:
		break;
	}
}

static __always_inline void
xdp_flowtable_snat_port(const struct flow_offload *flow,
			struct flow_ports *ports, void *data_end,
			__u8 proto, enum flow_offload_tuple_dir dir)
{
	__be16 port, nat_port;

	if (ports + 1 > data_end)
		return;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		port = ports->source;
		/* For original direction (FLOW_OFFLOAD_DIR_ORIGINAL):
		 * - tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_port contains
		 *   the source port used for the traffic transmitted by the
		 *   host.
		 * - tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_port contains
		 *   the destination port used for the traffic transmitted by
		 *   the host.
		 */
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_port);
		ports->source = nat_port;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		/* For reply direction (FLOW_OFFLOAD_DIR_REPLY):
		 * - tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_port
		 *   contains source port used for the traffic received by the
		 *   host.
		 * - tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_port
		 *   contains the destination port used for the traffic
		 *   received by the host.
		 */
		port = ports->dest;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_port);
		ports->dest = nat_port;
		break;
	default:
		return;
	}

	xdp_flowtable_update_port_csum(ports, data_end, proto, port, nat_port);
}

static __always_inline void
xdp_flowtable_dnat_port(const struct flow_offload *flow,
			struct flow_ports *ports, void *data_end, __u8 proto,
			enum flow_offload_tuple_dir dir)
{
	__be16 port, nat_port;

	if (ports + 1 > data_end)
		return;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		/* For original direction (FLOW_OFFLOAD_DIR_ORIGINAL):
		 * - tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_port contains
		 *   the source port used for the traffic transmitted by the
		 *   host.
		 * - tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_port contains
		 *   the destination port used for the traffic transmitted by
		 *   the host.
		 */
		port = ports->dest;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_port);
		ports->dest = nat_port;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		/* For reply direction (FLOW_OFFLOAD_DIR_REPLY):
		 * - tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_port
		 *   contains the source port used for the traffic received by
		 *   the host.
		 * - tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_port
		 *   contains destination port used for the traffic received by
		 *   the host.
		 */
		port = ports->source;
		bpf_core_read(&nat_port, bpf_core_type_size(nat_port),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_port);
		ports->source = nat_port;
		break;
	default:
		return;
	}

	xdp_flowtable_update_port_csum(ports, data_end, proto, port, nat_port);
}

static __always_inline void
xdp_flowtable_update_ipv4_csum(struct iphdr *iph, void *data_end,
			       __be32 addr, __be32 nat_addr)
{
	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

		if (tcph + 1 > data_end)
			break;

		tcph->check = csum_replace4((__u32)tcph->check, addr,
					    nat_addr);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)(iph + 1);

		if (udph + 1 > data_end)
			break;

		if (!udph->check)
			break;

		udph->check = csum_replace4((__u32)udph->check, addr,
					    nat_addr);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	default:
		break;
	}
}

static __always_inline void
xdp_flowtable_snat_ip(const struct flow_offload *flow, struct iphdr *iph,
		      void *data_end, enum flow_offload_tuple_dir dir)
{
	__be32 addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v4.s_addr);
		iph->saddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v4.s_addr);
		iph->daddr = nat_addr;
		break;
	default:
		return;
	}
	iph->check = csum_replace4((__u32)iph->check, addr, nat_addr);

	xdp_flowtable_update_ipv4_csum(iph, data_end, addr, nat_addr);
}

static __always_inline void
xdp_flowtable_get_dnat_ip(__be32 *addr, const struct flow_offload *flow,
			  enum flow_offload_tuple_dir dir)
{
	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr);
		break;
	}
}

static __always_inline void
xdp_flowtable_dnat_ip(const struct flow_offload *flow, struct iphdr *iph,
		      void *data_end, enum flow_offload_tuple_dir dir)
{
	__be32 addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr);
		iph->daddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr);
		iph->saddr = nat_addr;
		break;
	default:
		return;
	}
	iph->check = csum_replace4((__u32)iph->check, addr, nat_addr);

	xdp_flowtable_update_ipv4_csum(iph, data_end, addr, nat_addr);
}

static __always_inline void
xdp_flowtable_update_ipv6_csum(struct ipv6hdr *ip6h, void *data_end,
			       struct in6_addr *addr,
			       struct in6_addr *nat_addr)
{
	switch (ip6h->nexthdr) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (struct tcphdr *)(ip6h + 1);

		if (tcph + 1 > data_end)
			break;

		tcph->check = csum_replace16((__u32)tcph->check,
					     addr->in6_u.u6_addr32,
					     nat_addr->in6_u.u6_addr32);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (struct udphdr *)(ip6h + 1);

		if (udph + 1 > data_end)
			break;

		if (!udph->check)
			break;

		udph->check = csum_replace16((__u32)udph->check,
					     addr->in6_u.u6_addr32,
					     nat_addr->in6_u.u6_addr32);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
		break;
	}
	default:
		break;
	}
}

static __always_inline void
xdp_flowtable_snat_ipv6(const struct flow_offload *flow, struct ipv6hdr *ip6h,
			void *data_end, enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v6);
		ip6h->saddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v6);
		ip6h->daddr = nat_addr;
		break;
	default:
		return;
	}

	xdp_flowtable_update_ipv6_csum(ip6h, data_end, &addr, &nat_addr);
}

static __always_inline void
xdp_flowtable_get_dnat_ipv6(struct in6_addr *addr,
			    const struct flow_offload *flow,
			    enum flow_offload_tuple_dir dir)
{
	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6);
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		bpf_core_read(addr, sizeof(*addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6);
		break;
	}
}

static __always_inline void
xdp_flowtable_dnat_ipv6(const struct flow_offload *flow, struct ipv6hdr *ip6h,
			void *data_end, enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, nat_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->daddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6);
		ip6h->daddr = nat_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->saddr;
		bpf_core_read(&nat_addr, bpf_core_type_size(nat_addr),
			      &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6);
		ip6h->saddr = nat_addr;
		break;
	default:
		return;
	}

	xdp_flowtable_update_ipv6_csum(ip6h, data_end, &addr, &nat_addr);
}

static __always_inline void
xdp_flowtable_forward_ip(const struct flow_offload *flow, void *data,
			 void *data_end, struct flow_ports *ports,
			 enum flow_offload_tuple_dir dir,
			 unsigned long flags)
{
	struct iphdr *iph = data + sizeof(struct ethhdr);

	if (iph + 1 > data_end)
		return;

	if (flags & BIT(NF_FLOW_SNAT)) {
		xdp_flowtable_snat_port(flow, ports, data_end, iph->protocol,
					dir);
		xdp_flowtable_snat_ip(flow, iph, data_end, dir);
	}
	if (flags & BIT(NF_FLOW_DNAT)) {
		xdp_flowtable_dnat_port(flow, ports, data_end, iph->protocol,
					dir);
		xdp_flowtable_dnat_ip(flow, iph, data_end, dir);
	}

	ip_decrease_ttl(iph);
}

static __always_inline void
xdp_flowtable_forward_ipv6(const struct flow_offload *flow, void *data,
			   void *data_end, struct flow_ports *ports,
			   enum flow_offload_tuple_dir dir,
			   unsigned long flags)
{
	struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

	if (ip6h + 1 > data_end)
		return;

	if (flags & BIT(NF_FLOW_SNAT)) {
		xdp_flowtable_snat_port(flow, ports, data_end, ip6h->nexthdr,
					dir);
		xdp_flowtable_snat_ipv6(flow, ip6h, data_end, dir);
	}
	if (flags & BIT(NF_FLOW_DNAT)) {
		xdp_flowtable_dnat_port(flow, ports, data_end, ip6h->nexthdr,
					dir);
		xdp_flowtable_dnat_ipv6(flow, ip6h, data_end, dir);
	}

	ip6h->hop_limit--;
}

SEC("xdp")
int xdp_fwd_flowtable(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_offload_tuple_rhash *tuplehash;
	struct bpf_fib_lookup tuple = {
		.ifindex = ctx->ingress_ifindex,
	};
	void *data = (void *)(long)ctx->data;
	struct bpf_flowtable_opts opts = {};
	enum flow_offload_tuple_dir dir;
	struct ethhdr *eth = data;
	struct flow_offload *flow;
	struct flow_ports *ports;
	unsigned long flags;

	if (eth + 1 > data_end)
		return XDP_PASS;

	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IP): {
		struct iphdr *iph = data + sizeof(*eth);

		ports = (struct flow_ports *)(iph + 1);
		if (ports + 1 > data_end)
			return XDP_PASS;

		/* ip fragmented traffic */
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return XDP_PASS;

		/* ip options */
		if (iph->ihl * 4 != sizeof(*iph))
			return XDP_PASS;

		if (iph->ttl <= 1)
			return XDP_PASS;

		if (xdp_flowtable_check_tcp_state(ports, data_end,
						  iph->protocol) < 0)
			return XDP_PASS;

		tuple.family		= AF_INET;
		tuple.tos		= iph->tos;
		tuple.l4_protocol	= iph->protocol;
		tuple.tot_len		= bpf_ntohs(iph->tot_len);
		tuple.ipv4_src		= iph->saddr;
		tuple.ipv4_dst		= iph->daddr;
		tuple.sport		= ports->source;
		tuple.dport		= ports->dest;
		break;
	}
	case bpf_htons(ETH_P_IPV6): {
		struct in6_addr *src = (struct in6_addr *)tuple.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)tuple.ipv6_dst;
		struct ipv6hdr *ip6h = data + sizeof(*eth);

		ports = (struct flow_ports *)(ip6h + 1);
		if (ports + 1 > data_end)
			return XDP_PASS;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		if (xdp_flowtable_check_tcp_state(ports, data_end,
						  ip6h->nexthdr) < 0)
			return XDP_PASS;

		tuple.family		= AF_INET6;
		tuple.l4_protocol	= ip6h->nexthdr;
		tuple.tot_len		= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
		tuple.sport		= ports->source;
		tuple.dport		= ports->dest;
		break;
	}
	default:
		return XDP_PASS;
	}

	tuplehash = bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts));
	if (!tuplehash)
		return XDP_PASS;

	dir = tuplehash->tuple.dir;
	if (dir >= FLOW_OFFLOAD_DIR_MAX)
		return XDP_PASS;

	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
	if (bpf_core_read(&flags, sizeof(flags), &flow->flags))
		return XDP_PASS;

	if (tuplehash->tuple.xmit_type != FLOW_OFFLOAD_XMIT_NEIGH)
		return XDP_PASS;

	/* update the destination address in case of dnatting before
	 * performing the route lookup
	 */
	if (tuple.family == AF_INET6) {
		struct in6_addr *dst_addr = (struct in6_addr *)&tuple.ipv6_dst;

		xdp_flowtable_get_dnat_ipv6(dst_addr, flow, dir);
	} else {
		xdp_flowtable_get_dnat_ip(&tuple.ipv4_dst, flow, dir);
	}

	if (bpf_fib_lookup(ctx, &tuple, sizeof(tuple), 0) !=
	    BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_PASS;

	if (tuple.family == AF_INET6)
		xdp_flowtable_forward_ipv6(flow, data, data_end, ports, dir,
					   flags);
	else
		xdp_flowtable_forward_ip(flow, data, data_end, ports, dir,
					 flags);

	__builtin_memcpy(eth->h_dest, tuple.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, tuple.smac, ETH_ALEN);

	return bpf_redirect(tuple.ifindex, 0);
}

char _license[] SEC("license") = "GPL";
