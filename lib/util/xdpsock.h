/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright(c) 2019 - 2022 Intel Corporation.
 */

#ifndef XDPSOCK_H_
#define XDPSOCK_H_

#include <linux/if_xdp.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <time.h>
#include <sched.h>
#include <xdp/libxdp.h>
#include "params.h"

#define MAX_SOCKS 4
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 9728 /* Max frame size supported by many NICs */

enum xsk_benchmark_type {
	XSK_BENCH_RXDROP = 0,
	XSK_BENCH_TXONLY = 1,
	XSK_BENCH_L2FWD = 2,
};

enum xsk_program_mode {
	XSK_RXDROP,
	XSK_SWAP_MACS,
};

enum xsk_copy_mode {
	XSK_COPY_AUTO = 0,
	XSK_COPY_COPY = XDP_COPY,
	XSK_COPY_ZEROCOPY = XDP_ZEROCOPY,
};

enum xsk_clock {
	XSK_CLOCK_MONOTONIC = CLOCK_MONOTONIC,
	XSK_CLOCK_REALTIME = CLOCK_REALTIME,
	XSK_CLOCK_TAI = CLOCK_TAI,
	XSK_CLOCK_BOOTTIME = CLOCK_BOOTTIME,
};

enum xsk_sched_policy {
	XSK_SCHED_OTHER = SCHED_OTHER,
	XSK_SCHED_FIFO = SCHED_FIFO,
};

struct xsk_opts {
	__u32 queue_idx;
	__u32 interval;
	__u32 retries;
	__u32 frame_size;
	__u32 duration;
	__u32 batch_size;
	__u32 sched_prio;
	bool use_poll;
	bool no_need_wakeup;
	bool unaligned;
	bool extra_stats;
	bool quiet;
	bool app_stats;
	bool busy_poll;
	bool frags;
	bool shared_umem;
	char *irq_string;
	enum xdp_attach_mode attach_mode;
	enum xsk_program_mode program_mode;
	enum xsk_copy_mode copy_mode;
	enum xsk_clock clock;
	enum xsk_sched_policy sched_policy;
	struct iface iface;

	/* tx-only options */
	bool vlan_tag;
	bool timestamp;
	__u16 vlan_id;
	__u16 vlan_pri;
	__u16 tx_pkt_size;
	__u32 pkt_fill_pattern;
	__u32 pkt_count;
	__u64 tx_cycle_us;
	struct mac_addr dst_mac;
	struct mac_addr src_mac;
};

int xsk_validate_opts(const struct xsk_opts *opt);

#endif /* XDPSOCK_H */
