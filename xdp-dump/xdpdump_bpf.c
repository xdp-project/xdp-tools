// SPDX-License-Identifier: GPL-2.0

/*****************************************************************************
 * Include files
 *****************************************************************************/
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_trace_helpers.h>
#include "xdpdump.h"

/*****************************************************************************
 * (re)definition of kernel data structures for use with BTF
 *****************************************************************************/
struct net_device {
	/* Structure does not need to contain all entries,
	 * as "preserve_access_index" will use BTF to fix this...
	 */
	int ifindex;
} __attribute__((preserve_access_index));

struct xdp_rxq_info {
	/* Structure does not need to contain all entries,
	 * as "preserve_access_index" will use BTF to fix this...
	 */
	struct net_device *dev;
	__u32 queue_index;
} __attribute__((preserve_access_index));

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	unsigned long handle;
	struct xdp_rxq_info *rxq;
} __attribute__((preserve_access_index));

/*****************************************************************************
 * Local definitions and global variables
 *****************************************************************************/
struct bpf_map_def SEC("maps") xdpdump_perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = MAX_CPUS,
};

/*****************************************************************************
 * trace_to_perf_buffer()
 *****************************************************************************/
static inline void trace_to_perf_buffer(struct xdp_buff *xdp, bool fexit)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct pkt_trace_metadata metadata;

	if (data >= data_end)
		return;

	metadata.ifindex = xdp->rxq->dev->ifindex;
	metadata.rx_queue = xdp->rxq->queue_index;
	metadata.pkt_len = (__u16)(data_end - data);
	metadata.cap_len = metadata.pkt_len;
	metadata.flags = 0;

	if (fexit)
		metadata.flags |= MDF_DIRECTION_FEXIT;

	bpf_xdp_output(xdp, &xdpdump_perf_map,
		       ((__u64) metadata.cap_len << 32) |
		       BPF_F_CURRENT_CPU,
		       &metadata, sizeof(metadata));
}

/*****************************************************************************
 * Tracx_on_entry()
 *****************************************************************************/
SEC("fentry/func")
int BPF_PROG(trace_on_entry, struct xdp_buff *xdp)
{
	trace_to_perf_buffer(xdp, false);
	return 0;
}

/*****************************************************************************
 * trace_on_exit()
 *****************************************************************************/
SEC("fexit/func")
int BPF_PROG(trace_on_exit, struct xdp_buff *xdp, int ret)
{
	trace_to_perf_buffer(xdp, true);
	return 0;
}

/*****************************************************************************
 * License
 *****************************************************************************/
char _license[] SEC("license") = "GPL";
