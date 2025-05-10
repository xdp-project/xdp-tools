/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Frey Alfredsson <freysteinn@freysteinn.com> */
/* Based on code by Jesper Dangaard Brouer <brouer@redhat.com> */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include "parsing_helpers.h"

/*
 * This example eBPF code mirrors the TC u32 rules set in the runner.sh
 * script, where the script gives different rate limits depending on if the TCP
 * traffic is for ports 8080 or 8081. It must be loaded with the direct-action
 * flag on TC to function, as this is a Qdisc classifier, not a Qdisc action. The
 * runner.sh script shows an example of how it is loaded and used.
 */

SEC("classifier")
int  cls_filter(struct __sk_buff *skb)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int tcp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	skb->tc_classid = 0x30; /* Default class */

	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_TCP)
			goto out;
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_TCP)
			goto out;
	} else {
		goto out;
	}

	/* Classify TCP ports 8080 and 8081 */
	tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
	if (tcp_type < 0 ) goto out;
	if (tcphdr + 1 > data_end) {
		goto out;
	}

	switch (tcphdr->dest) {
	case bpf_htons(8080):
		skb->tc_classid = 0x10; /* Handles are always in hex */
		break;
	case bpf_htons(8081):
		skb->tc_classid = 0x20;
	}

 out:
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
