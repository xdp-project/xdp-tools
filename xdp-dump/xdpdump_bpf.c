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
 * Macros
 *****************************************************************************/
#define min(x,y) ((x)<(y) ? x : y)

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
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, int);
	__type(value, __u32);
} xdpdump_perf_map SEC(".maps");


/*****************************************************************************
 * .data section value storing the capture configuration
 *****************************************************************************/
struct trace_configuration trace_cfg SEC(".data");

/*****************************************************************************
 * trace_to_perf_buffer()
 *****************************************************************************/
static inline void trace_to_perf_buffer(struct xdp_buff *xdp, bool fexit,
					int action)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct pkt_trace_metadata metadata;

	if (data >= data_end ||
	    trace_cfg.capture_if_ifindex != xdp->rxq->dev->ifindex)
		return;

	metadata.prog_index = trace_cfg.capture_prog_index;
	metadata.ifindex = xdp->rxq->dev->ifindex;
	metadata.rx_queue = xdp->rxq->queue_index;
	metadata.pkt_len = (__u16)(data_end - data);
	metadata.cap_len = min(metadata.pkt_len, trace_cfg.capture_snaplen);
	metadata.action = action;
	metadata.flags = 0;

	if (fexit)
		metadata.flags |= MDF_DIRECTION_FEXIT;

	bpf_xdp_output(xdp, &xdpdump_perf_map,
		       ((__u64) metadata.cap_len << 32) |
		       BPF_F_CURRENT_CPU,
		       &metadata, sizeof(metadata));
}

/*****************************************************************************
 * trace_on_entry()
 *****************************************************************************/
SEC("fentry/func")
int BPF_PROG(trace_on_entry, struct xdp_buff *xdp)
{
	trace_to_perf_buffer(xdp, false, 0);
	return 0;
}

/*****************************************************************************
 * trace_on_exit()
 *****************************************************************************/
SEC("fexit/func")
int BPF_PROG(trace_on_exit, struct xdp_buff *xdp, int ret)
{
	trace_to_perf_buffer(xdp, true, ret);
	return 0;
}

/*****************************************************************************
 * License
 *****************************************************************************/
char _license[] SEC("license") = "GPL";
