/* SPDX-License-Identifier: GPL-2.0 */

#define XDP_STATS_MAP_PINNING LIBBPF_PIN_NONE

#include "xdp-trafficgen.h"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_sample_shared.h>
#include <xdp/xdp_sample.bpf.h>
#include <xdp/xdp_sample_common.bpf.h>
#include <xdp/parsing_helpers.h>

#if defined(HAVE_LIBBPF_BPF_PROGRAM__FLAGS) && defined(DEBUG)
/* We use the many-argument version of bpf_printk() for debugging, so only
 * enable it if we have the libbpf helper that selects the vprintf version. This
 * was introduced in libbpf 0.6.0, which is the same versionn as the
 * bpf_program__flags() method, so use that as an indicator since we don't
 * feature detect on the BPF helpers themselves.
 */
#define TCP_DEBUG
#endif

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct trafficgen_state);
} state_map SEC(".maps");


const volatile struct trafficgen_config config;

static void update_checksum(__u16 *sum, __u32 diff)
{
	/* We use the RFC 1071 method for incremental checksum updates
	 * because that can be used directly with the 32-bit sequence
	 * number difference (relying on folding for large differences)
	 */
	__u32 cksum = diff + (__u16)~bpf_ntohs(*sum);

	while (cksum > 0xffff)
		cksum = (cksum & 0xffff) + (cksum >> 16);
	*sum = bpf_htons(~cksum);
}

static __u16 csum_fold_helper(__u32 csum) {
	csum = (csum & 0xffff) + (csum >> 16);
        return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	__u32 key = bpf_get_smp_processor_id();;
	struct datarec *rec;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;

	NO_TEAR_INC(rec->xdp_redirect);

	return bpf_redirect(config.ifindex_out, 0);
}

SEC("xdp")
int xdp_redirect_update_port(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct trafficgen_state *state;
	__u16 cur_port, port_diff;
	int action = XDP_ABORTED;
	struct datarec *rec;
	struct udphdr *hdr;
	__u32 key = 0;

	hdr = data + (sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	if (hdr + 1 > data_end)
		goto out;

	state = bpf_map_lookup_elem(&state_map, &key);
	if (!state)
		goto out;

	key = bpf_get_smp_processor_id();
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		goto out;

	cur_port = bpf_ntohs(hdr->dest);
	port_diff = state->next_port - cur_port;
	if (port_diff) {
		update_checksum(&hdr->check, port_diff);
		hdr->dest = bpf_htons(state->next_port);
	}
	if (state->next_port++ >= config.port_start + config.port_range - 1)
		state->next_port = config.port_start;

	action = bpf_redirect(config.ifindex_out, 0);
	NO_TEAR_INC(rec->processed);
out:
	return action;
}

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct tcp_flowkey);
	__type(value, struct tcp_flowstate);
} flow_state_map SEC(".maps");

static int cmp_ipaddr(struct in6_addr *a_, struct in6_addr *b_)
{
	__u8 *a = (void *)a_, *b = (void *)b_;
	int i;

	for (i = 0; i < sizeof(struct in6_addr); i++) {
		if (*a > *b)
			return -1;
		if (*a < *b)
			return 1;
		a++;
		b++;
	}
	return 0;
}

static inline __u8 before(__u32 seq1, __u32 seq2)
{
        return (__s32)(seq1 - seq2) < 0;
}

/* Fixed 2 second timeout */
#define TCP_RTO 2000000000UL

SEC("xdp")
int xdp_handle_tcp_recv(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct tcp_flowstate *fstate, new_fstate = {};
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct trafficgen_state *state;
	struct tcp_flowkey key = {};
	int eth_type, ip_type, err;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	int action = XDP_PASS;
	struct ethhdr *eth;
	__u8 new_match;
	__u32 ack_seq;
	int i;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IPV6))
		goto out;

	ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	if (ip_type != IPPROTO_TCP)
		goto out;

	if (parse_tcphdr(&nh, data_end, &tcphdr) < 0)
		goto out;

	state = bpf_map_lookup_elem(&state_map, &key);
	if (!state)
		goto out;

	/* swap dst and src for received packet */
	key.dst_ip = ipv6hdr->saddr;
	key.dst_port = tcphdr->source;

	new_match = !cmp_ipaddr(&key.dst_ip, &state->flow_key.dst_ip) && key.dst_port == state->flow_key.dst_port;

	key.src_ip = ipv6hdr->daddr;
	key.src_port = tcphdr->dest;

	fstate = bpf_map_lookup_elem(&flow_state_map, &key);
	if (!fstate) {
		if (!new_match)
			goto out;

		new_fstate.flow_state = FLOW_STATE_NEW;
		new_fstate.seq = bpf_ntohl(tcphdr->ack_seq);
		for (i = 0; i < ETH_ALEN; i++) {
			new_fstate.dst_mac[i] = eth->h_source[i];
			new_fstate.src_mac[i] = eth->h_dest[i];
		}

		err = bpf_map_update_elem(&flow_state_map, &key, &new_fstate, BPF_NOEXIST);
		if (err)
			goto out;

		fstate = bpf_map_lookup_elem(&flow_state_map, &key);
		if (!fstate)
			goto out;
	}

	ack_seq = bpf_ntohl(tcphdr->ack_seq);
#ifdef TCP_DEBUG
	bpf_printk("Got state seq %u ack_seq %u new %u seq %u new %u window %u\n",
		   fstate->seq,
		   fstate->ack_seq, ack_seq,
		   fstate->rcv_seq, bpf_ntohl(tcphdr->seq), bpf_htons(tcphdr->window));
#endif

	bpf_spin_lock(&fstate->lock);

	if (fstate->ack_seq == ack_seq)
		fstate->dupack++;

	fstate->window = bpf_ntohs(tcphdr->window);
	fstate->ack_seq = ack_seq;
	fstate->rcv_seq = bpf_ntohl(tcphdr->seq);
	if (tcphdr->syn)
		fstate->rcv_seq++;

	if (tcphdr->fin || tcphdr->rst)
		fstate->flow_state = FLOW_STATE_DONE;

	/* If we've taken over the flow management, (after the handshake), drop
	 * the packet
	 */
	if (fstate->flow_state >= FLOW_STATE_RUNNING)
		action = XDP_DROP;
	bpf_spin_unlock(&fstate->lock);
out:
	return action;
}

SEC("xdp")
int xdp_redirect_send_tcp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 new_seq, ack_seq, window;
	struct trafficgen_state *state;
	struct tcp_flowstate *fstate;
	int action = XDP_ABORTED;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	struct datarec *rec;
	__u8 resend = 0;
#ifdef TCP_DEBUG
	__u8 print = 0;
#endif
	__u16 pkt_len;
	__u32 key = 0;
	__u64 now;

	ipv6hdr = data + sizeof(struct ethhdr);
	tcphdr = data + (sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	if (tcphdr + 1 > data_end || ipv6hdr + 1 > data_end)
		goto ret;

	pkt_len = bpf_ntohs(ipv6hdr->payload_len) - sizeof(*tcphdr);

	state = bpf_map_lookup_elem(&state_map, &key);
	if (!state)
		goto ret;

	key = bpf_get_smp_processor_id();
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		goto ret;

	fstate = bpf_map_lookup_elem(&flow_state_map, (const void *)&state->flow_key);
	if (!fstate)
		goto out;

	now = bpf_ktime_get_coarse_ns();

	bpf_spin_lock(&fstate->lock);

	if (fstate->flow_state != FLOW_STATE_RUNNING) {
		action = XDP_DROP;
		bpf_spin_unlock(&fstate->lock);
		goto out;
	}

	/* reset sequence on packet loss */
	if (fstate->dupack || (fstate->last_progress &&
			       now - fstate->last_progress > TCP_RTO)) {
		fstate->seq = fstate->ack_seq;
		fstate->dupack = 0;
	}
	new_seq = fstate->seq;
	ack_seq = fstate->ack_seq;
	window = fstate->window << fstate->wscale;
#ifdef TCP_DEBUG
	if (fstate->last_print != fstate->seq) {
		fstate->last_print = fstate->seq;
		print = 1;
	}
#endif

	if (!before(new_seq + pkt_len, ack_seq + window)) {
		/* We caught up to the end up the RWIN, spin until ACKs come
		 * back opening up the window
		 */
		action = XDP_DROP;
		bpf_spin_unlock(&fstate->lock);
#ifdef TCP_DEBUG
		if (print)
			bpf_printk("Dropping because %u isn't before %u (ack_seq %u wnd %u)",
				   new_seq + pkt_len, ack_seq + window, ack_seq, window);
#endif
		goto out;
	}

	if (!before(new_seq, fstate->highest_seq)) {
		fstate->highest_seq = new_seq;
	} else {
		resend = 1;
		fstate->retransmits++;
	}
	fstate->seq = new_seq + pkt_len;
	fstate->last_progress = now;
	bpf_spin_unlock(&fstate->lock);

	new_seq = bpf_htonl(new_seq);
	if (new_seq != tcphdr->seq) {
		__u32 csum;
		csum = bpf_csum_diff(&tcphdr->seq, sizeof(__u32),
				     &new_seq, sizeof(new_seq), ~tcphdr->check);

		tcphdr->seq = new_seq;
		tcphdr->check = csum_fold_helper(csum);
	}

	action = bpf_redirect(config.ifindex_out, 0);
out:
	/* record retransmissions as XDP_TX return codes until we get better stats */
	if (resend)
		NO_TEAR_INC(rec->issue);

	if (action == XDP_REDIRECT)
		NO_TEAR_INC(rec->xdp_redirect);
	else
		NO_TEAR_INC(rec->dropped);
ret:
	return action;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}
