// SPDX-License-Identifier: GPL-2.0

#include <bpf/vmlinux.h>
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

SEC("tp_btf/xdp_cpumap_kthread")
int BPF_PROG(tp_xdp_cpumap_kthread, int map_id, unsigned int processed,
	     unsigned int drops, int sched, struct xdp_cpumap_stats *xdp_stats)
{
	bpf_printk("Stats: %d %u %u %d %d\n",
		   map_id, processed, drops, sched, xdp_stats->pass);
	return 0;
}

char _license[] SEC("license") = "GPL";
