// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

SEC("tc")  // Changed section name
int dummy(struct __sk_buff *skb)
{
    return TC_ACT_OK;;
}

char __license[] SEC("license") = "GPL";
