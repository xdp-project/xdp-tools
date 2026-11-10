// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define AF_INET	2
#define AF_INET6	10

#define IPV6_FLOWINFO_MASK              bpf_htons(0x0FFFFFFF)

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

#include "xdp_forward_vlan.h"

/*
 * Without VLAN-aware bpf_fib_lookup() in the kernel, a route that egresses
 * through a VLAN upper device resolves to that device's ifindex, which XDP
 * cannot transmit through. Userspace enumerates the VLAN uppers and fills
 * this map, keyed by the VLAN device ifindex, with the underlying physical
 * ifindex and the VLAN id, so the program can redirect through the physical
 * device with the right tag applied.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct vlan_info));
	__uint(max_entries, 4096); /* arbitrary; overflow falls back to the stack path */
} vlan_map SEC(".maps");

/*
 * Set by the loader, before the object is loaded, to the number of usable
 * VLAN uppers on the configured interfaces. Frozen at load time, so when it
 * is zero the verifier removes every VLAN branch below, leaving only the
 * gate itself on the fast path.
 */
volatile const __u32 vlans_configured;

/*
 * Only untagged frames and single-tagged 802.1Q are reshaped. 802.1ad and
 * stacked tags go back to the stack, which forwards them correctly; the
 * reshape below would rewrite or pop just the outer tag. Runs before any
 * packet mutation so a bail leaves the frame exactly as received.
 */
static __always_inline int xdp_fwd_vlan_fwdable(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct vlan_hdr *vhdr;

	if (eth + 1 > data_end)
		return -1;

	if (eth->h_proto == bpf_htons(ETH_P_8021AD))
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_8021Q))
		return 0;

	vhdr = (void *)(eth + 1);
	if (vhdr + 1 > data_end)
		return -1;
	if (vhdr->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q) ||
	    vhdr->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021AD))
		return -1;

	return 0;
}

/*
 * Reshape the frame's VLAN encapsulation to match the egress device;
 * egress_vid == 0 means the egress device is untagged. Only the VID is
 * set on egress; priority (PCP) and DEI are not carried over. The caller
 * has already checked xdp_fwd_vlan_fwdable(), so a tagged frame here is
 * single 802.1Q. A push or pop moves the packet head, which invalidates
 * every packet pointer the caller holds, so this runs after the TTL
 * update and the caller re-reads the header afterwards. Push and pop
 * leave h_dest/h_source undefined; the caller must stamp both from the
 * FIB result after this returns.
 */
static __always_inline int xdp_fwd_set_vlan(struct xdp_md *ctx,
					    __u16 egress_vid)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct vlan_hdr *vhdr;
	__be16 inner_proto;
	bool ingress_tagged;

	if (eth + 1 > data_end)
		return -1;

	ingress_tagged = eth->h_proto == bpf_htons(ETH_P_8021Q);

	if (ingress_tagged && egress_vid) {
		vhdr = (void *)(eth + 1);
		if (vhdr + 1 > data_end)
			return -1;
		vhdr->h_vlan_TCI = bpf_htons(egress_vid & 0x0fff);
		return 0;
	}

	if (ingress_tagged && !egress_vid) {
		vhdr = (void *)(eth + 1);
		if (vhdr + 1 > data_end)
			return -1;
		inner_proto = vhdr->h_vlan_encapsulated_proto;

		if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)))
			return -1;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if (eth + 1 > data_end)
			return -1;
		eth->h_proto = inner_proto;
		return 0;
	}

	if (!ingress_tagged && egress_vid) {
		inner_proto = eth->h_proto;

		if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
			return -1;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if (eth + 1 > data_end)
			return -1;
		vhdr = (void *)(eth + 1);
		if (vhdr + 1 > data_end)
			return -1;

		eth->h_proto = bpf_htons(ETH_P_8021Q);
		vhdr->h_vlan_TCI = bpf_htons(egress_vid & 0x0fff);
		vhdr->h_vlan_encapsulated_proto = inner_proto;
		return 0;
	}

	return 0;
}

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
	struct hdr_cursor nh = { .pos = data };
	struct bpf_fib_lookup fib_params;
	int rc, eth_type, ip_type;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	struct iphdr *iph;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iph);
		if (ip_type < 0)
			return XDP_PASS;

		if (iph->ttl <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= ip_type;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_type < 0)
			return XDP_PASS;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip_type;
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
		/* one rodata read serves all three gates below */
		__u32 vlans = vlans_configured;
		__u16 egress_vid = 0;

		/* Verify egress index has been configured as TX-port.
		 * (Note: User can still have inserted an egress ifindex that
		 * doesn't support XDP xmit, which will result in packet drops).
		 *
		 * Note: lookup in devmap supported since 0cdbb4b09a0.
		 * If not supported will fail with:
		 *  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
		 */
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex)) {
			/*
			 * A stock kernel resolves a VLAN egress to the VLAN
			 * device's ifindex, never a TX-port; translate to the
			 * physical device and remember the tag. Ordered after
			 * the TX-port check so untagged traffic pays nothing.
			 */
			struct vlan_info *vinfo;

			if (!vlans)
				return XDP_PASS;

			vinfo = bpf_map_lookup_elem(&vlan_map,
						    &fib_params.ifindex);
			if (!vinfo)
				return XDP_PASS;
			egress_vid = vinfo->vlan_id;
			fib_params.ifindex = vinfo->phys_ifindex;
			if (!bpf_map_lookup_elem(&xdp_tx_ports,
						 &fib_params.ifindex))
				return XDP_PASS;
		}

		/* bail while the frame is still untouched */
		if (vlans && xdp_fwd_vlan_fwdable(ctx) < 0)
			return XDP_PASS;

		/*
		 * Decrement TTL before any VLAN reshape below: a push or pop
		 * moves the packet head and invalidates iph/ip6h.
		 */
		if (eth_type == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (eth_type == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		if (vlans) {
			/*
			 * The TTL is already decremented: a frame that fails
			 * here must be dropped, not passed, or the stack
			 * would forward it and decrement again.
			 */
			if (xdp_fwd_set_vlan(ctx, egress_vid) < 0)
				return XDP_DROP;

			/* pointers invalidated by a possible head adjust;
			 * re-read
			 */
			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
			eth = data;
			if (eth + 1 > data_end)
				return XDP_DROP;
		}

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
