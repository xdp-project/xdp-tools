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
	static const char fmt[] = "Stats: %d %u %u %d %d\n";
	unsigned long long args[] = {
		map_id, processed, drops, sched, xdp_stats->pass
	};

	bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
	return 0;
}

char _license[] SEC("license") = "GPL";
