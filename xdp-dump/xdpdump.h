// SPDX-License-Identifier: GPL-2.0

/******************************************************************************
 * Multiple include protection
 ******************************************************************************/
#ifndef _XDPDUMP_H_
#define _XDPDUMP_H_

/******************************************************************************
 * General definitions
 ******************************************************************************/
#define PERF_MAX_WAKEUP_EVENTS   64
#define PERF_MMAP_PAGE_COUNT	256
#define MAX_CPUS		256

/******************************************************************************
 * General used macros
 ******************************************************************************/
#ifndef __packed
#define __packed __attribute__((packed))
#endif

/*****************************************************************************
 * trace configuration structure
 *****************************************************************************/
struct trace_configuration {
	__u32 capture_if_ifindex;
	__u32 capture_snaplen;
	__u32 capture_prog_index;
};

/*****************************************************************************
 * perf data structures
 *****************************************************************************/
#define MDF_DIRECTION_FEXIT 1

struct pkt_trace_metadata {
	__u32 ifindex;
	__u32 rx_queue;
	__u16 pkt_len;
	__u16 cap_len;
	__u16 flags;
	__u16 prog_index;
	int   action;
} __packed;

#ifndef __bpf__
struct perf_sample_event {
	struct perf_event_header header;
	__u64 time;
	__u32 size;
	struct pkt_trace_metadata metadata;
	unsigned char packet[];
};

struct perf_lost_event {
	struct perf_event_header header;
	__u64 id;
	__u64 lost;
};
#endif

/******************************************************************************
 * End-of include file
 ******************************************************************************/
#endif /* _XDPDUMP_H_ */

