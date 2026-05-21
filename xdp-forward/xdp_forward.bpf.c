// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define AF_INET	2
#define AF_INET6	10

#define IPV6_FLOWINFO_MASK              bpf_htons(0x0FFFFFFF)

#define BPF_FIB_LOOKUP_VLAN            (1U << 6)
#define BPF_FIB_LOOKUP_RESOLVE_VLAN    (1U << 7)

struct vlan_info {
    __u16 vlan_id;          // VLAN ID
    int   phys_ifindex;     // Physical interface index
    int   vlan_ifindex;     // VLAN interface index
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);  // it's read only, no need for locks at bpf side
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vlan_info));
    __uint(max_entries, 16*64);  // 16 vlans per interface, 64 interfaces
} vlan_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
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

#ifdef VLANS_USERSPACE
static __always_inline int set_vlan_params(struct bpf_fib_lookup *fib_params, __u32 vlan_ifindex)
{
	/**
	 * set_vlan_params - When unpatched kernel is used, routing
	 * lookup for VLANed networks returns ifindex of VLAN interface.
	 * XDP doesn't support VLAN interfaces, physical needs to be used.
	 * This functions lookups the physical interface and VLAN id
	 * in the map (provided by userspace) and sets them in the
	 * fib_params struct, which are set to 0 by bpf_fib_lookup().
	 */
	struct vlan_info *vinfo;
	vinfo = bpf_map_lookup_elem(&vlan_map, &vlan_ifindex);
	if (!vinfo)
		return -1;

	fib_params->ifindex = vinfo->phys_ifindex;
	fib_params->h_vlan_TCI = vinfo->vlan_id;

	return 0;
}
#endif

static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, __u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
#if defined(VLANS_USERSPACE) || defined(VLANS_PATCHED)
	struct vlan_hdr *vhdr = NULL;
#endif
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
#if defined(VLANS_USERSPACE) || defined(VLANS_PATCHED)
	if (h_proto == bpf_htons(ETH_P_8021Q)) {
		vhdr = data + nh_off;
		if (vhdr + 1 > data_end)
			return XDP_DROP;

		fib_params.h_vlan_proto = bpf_ntohs(h_proto);
		fib_params.h_vlan_TCI = bpf_ntohs(vhdr->h_vlan_TCI);

		h_proto = vhdr->h_vlan_encapsulated_proto;
		nh_off += sizeof(struct vlan_hdr);
	}
#endif
#ifdef VLANS_PATCHED
	flags |= BPF_FIB_LOOKUP_RESOLVE_VLAN; // works for all the inf type combinations
#endif
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
#ifdef VLANS_USERSPACE
		set_vlan_params(&fib_params, fib_params.ifindex);
#endif

		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex))
			return XDP_PASS;

		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

#if defined(VLANS_USERSPACE) || defined(VLANS_PATCHED)
		if (vhdr && fib_params.h_vlan_TCI) {
			// case: tagged inf to tagged inf, requires just rewritting vlan hdr
			vhdr->h_vlan_TCI = bpf_htons(fib_params.h_vlan_TCI); // TODO: why??? shouldnt h_vlan_TCI be in network order?
			vhdr->h_vlan_encapsulated_proto = fib_params.h_vlan_proto;

		} else if (vhdr && !fib_params.h_vlan_TCI) {
			// case: tagged inf to untagged inf, requires removing vlan hdr
			__be16 inner_proto = vhdr->h_vlan_encapsulated_proto;

			if (bpf_xdp_adjust_head(ctx, sizeof(struct vlan_hdr)))
				return XDP_PASS; // can't remove header

			data = (void *)(long)ctx->data;  // ptrs are now invalid, re-evaluate
			data_end = (void *)(long)ctx->data_end;

			if (data + sizeof(struct ethhdr) > data_end)
				return XDP_PASS;

			eth = data;
			eth->h_proto = inner_proto;

		} else if (!vhdr && fib_params.h_vlan_TCI) {
			// case: untagged inf to tagged inf, requires adding vlan hdr
			__be16 orig_proto = eth->h_proto;

			// Negative value adds space at the beginning
			if (bpf_xdp_adjust_head(ctx, -((__s32)sizeof(struct vlan_hdr))))
				return XDP_PASS; // can't add header

			data = (void *)(long)ctx->data;  // ptrs are now invalid, re-evaluate
			data_end = (void *)(long)ctx->data_end;

			if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end)
				return XDP_PASS;  // not enough space for vhdr, let kernel process it

			eth = data;
			eth->h_proto = bpf_htons(ETH_P_8021Q);

			vhdr = data + sizeof(struct ethhdr);
			vhdr->h_vlan_TCI = bpf_htons(fib_params.h_vlan_TCI);
			vhdr->h_vlan_encapsulated_proto = orig_proto;
		}
#endif

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

char _license[] SEC("license") = "GPL";
