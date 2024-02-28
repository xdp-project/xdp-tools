// SPDX-License-Identifier: GPL-2.0
/* Original xdp_fwd sample Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <xdp/parsing_helpers.h>

#include "xdp-forward.h"

#define AF_INET	2
#define AF_INET6	10

#define IPV6_FLOWINFO_MASK              bpf_htons(0x0FFFFFFF)
#define CLOCK_MONOTONIC			1
#define META_COOKIE_VAL 0x4242424242424242UL

#define MAX_TX_PORTS 64
#define TX_BATCH_SIZE 8

#define IFINDEX_MASK 0xFFFFFFFF
#define STATE_KEY(cpu, ifindex) (((__u64)cpu << 32) + ifindex)

#define PORT_QUEUE_THRESHOLD (1024 * 1024 * 1024)

#define BPF_MAP_TYPE_XDP_FIFO 36

#define MAP_PTR(map) ((struct bpf_map *)&map)

extern struct xdp_frame *xdp_packet_dequeue(struct bpf_map *map, __u64 flags,
					    __u64 *rank) __ksym;
extern int xdp_packet_drop(struct xdp_frame *pkt) __ksym;
extern int xdp_packet_send(struct xdp_frame *pkt, int ifindex, __u64 flags) __ksym;
extern int xdp_packet_flush(void) __ksym;
extern int bpf_dynptr_from_xdp_frame(struct xdp_frame *xdp, __u64 flags,
                                     struct bpf_dynptr *ptr__uninit) __ksym;

struct port_state {
	__u64 outstanding_bytes;
	struct bpf_timer timer;
	__u32 tx_port_idx;
};

struct meta_val {
	__u64 state_key;
	__u64 cookie;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct port_state);
	__uint(max_entries, MAX_TX_PORTS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dst_port_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XDP_FIFO);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 10240);
	__uint(map_extra, MAX_TX_PORTS);
} xdp_queues SEC(".maps");

static int xdp_timer_cb(struct bpf_map *map, __u64 *key, struct bpf_timer *timer)
{
	struct port_state *state;
	struct xdp_frame *pkt;
	int i, tgt_ifindex;
	__u64 index;

	bpf_printk("BPF timer cb - key %lu\n", *key);

	state = bpf_map_lookup_elem(map, key);
	if (!state) {
		bpf_printk("xdp_timer_cb: No state found for key %lu\n", *key);
		goto out;
	}

	index = state->tx_port_idx;
	tgt_ifindex = (*key) & IFINDEX_MASK;
	bpf_printk("xdp_timer_cb: tgt_ifindex %d tx_port_idx %lu\n", tgt_ifindex, index);

	for (i = 0; i < TX_BATCH_SIZE; i++) {
		pkt = xdp_packet_dequeue(MAP_PTR(xdp_queues), index, NULL);
		if (!pkt) {
			bpf_printk("xdp_timer_cb: No packet returned\n");
			break;
		}

		bpf_printk("xdp_timer_cb: Sending to ifindex %d\n", tgt_ifindex);
		xdp_packet_send(pkt, tgt_ifindex, 0);
	}

	xdp_packet_flush();
out:
	return 0;
}

static __u32 next_port_idx = 0;

static int init_tx_port(int ifindex, __u32 cpu)
{
	__u64 state_key = STATE_KEY(cpu, ifindex);
	struct port_state *state, new_state = {};
	int ret;

	if (next_port_idx >= MAX_TX_PORTS)
		return -E2BIG;

	new_state.tx_port_idx = next_port_idx++;

	ret = bpf_map_update_elem(&dst_port_state, &state_key, &new_state, 0);
	if (ret)
		return ret;

	state = bpf_map_lookup_elem(&dst_port_state, &state_key);
	if (!state)
		return -1;

	ret = bpf_timer_init(&state->timer, &dst_port_state, CLOCK_MONOTONIC) ?:
		      bpf_timer_set_callback(&state->timer, xdp_timer_cb)     ?:
										0;
	if (!ret)
		bpf_printk("TX port init OK ifindex %d cpu %u\n", ifindex, cpu);

	return ret;
}

static __always_inline bool forward_dst_enabled(int ifindex)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u64 state_key = STATE_KEY(cpu, ifindex);

	return !!bpf_map_lookup_elem(&dst_port_state, &state_key);
}

static bool port_can_xmit(struct port_state *state)
{
	return state->outstanding_bytes < PORT_QUEUE_THRESHOLD;
}

static int forward_to_dst(struct xdp_md *ctx, int ifindex)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u64 state_key = STATE_KEY(cpu, ifindex);
	struct port_state *state;
	void *data, *data_meta;
	struct meta_val *mval;
	int ret;

	state = bpf_map_lookup_elem(&dst_port_state, &state_key);
	if (!state)
		return XDP_DROP;

	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(*mval)))
		return XDP_ABORTED;

	data  = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;
	mval = data_meta;

	if (mval + 1 > data)
		return XDP_ABORTED;

	mval->state_key = state_key;
	mval->cookie = META_COOKIE_VAL;

	ret = bpf_redirect_map(&xdp_queues, state->tx_port_idx, 0);

	bpf_printk("Redirect to XDP queue idx %d: %d\n", state->tx_port_idx, ret);

	if (ret == XDP_REDIRECT && port_can_xmit(state)) {
		int r = bpf_timer_start(&state->timer, 0 /* call asap */, 0);
		bpf_printk("Started BPF timer: %d\n", r);
	}

	return ret;
}

SEC("raw_tracepoint/xdp_frame_return")
int xdp_check_return(struct bpf_raw_tracepoint_args* ctx)
{
	struct xdp_frame *frm = (struct xdp_frame *)ctx->args[0];
	struct port_state *state;
	struct meta_val meta;
	__u32 metasize;
	__u16 pkt_len;
	bool can_xmit;
	void *data;

	pkt_len = BPF_CORE_READ(frm, len);
	metasize = BPF_CORE_READ(frm, metasize);
	if (metasize != sizeof(meta))
		goto out;

	data = BPF_CORE_READ(frm, data);
	if (!data)
		goto out;

	if (bpf_probe_read_kernel(&meta, sizeof(meta), data-metasize))
		goto out;

	if (meta.cookie != META_COOKIE_VAL)
		goto out;

	state = bpf_map_lookup_elem(&dst_port_state, &meta.state_key);
	if (!state)
		goto out;

	can_xmit = port_can_xmit(state);
	state->outstanding_bytes -= pkt_len;

	if (!can_xmit && port_can_xmit(state))
		bpf_timer_start(&state->timer, 0, 0);

out:
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
		if (!forward_dst_enabled(fib_params.ifindex))
			return XDP_PASS;

		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return forward_to_dst(ctx, fib_params.ifindex);
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

SEC("xdp")
int init_port(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* we need this program to be an XDP type program, so we stash the
	 * parameters in the data member and call it using BPF_PROG_RUN
	 */
	struct port_init_config *cfg = data;

	if (cfg + 1 > data_end)
		return XDP_ABORTED;

	return init_tx_port(cfg->ifindex, cfg->cpu) ? XDP_ABORTED : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
