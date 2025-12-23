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

struct xsk_ctx {
	const struct xsk_opts opt;

	unsigned long prev_time;
	long tx_cycle_diff_min;
	long tx_cycle_diff_max;
	double tx_cycle_diff_ave;
	long tx_cycle_cnt;
	unsigned long tx_cycle_ns;

	unsigned long start_time;
	unsigned long duration;
	bool benchmark_done;

	__u32 irq_no;
	int irqs_at_init;
	__u32 sequence;
	int frames_per_pkt;
	int poll_timeout;
	__u32 retries;

	struct xdp_program *xdp_prog;
	struct xsk_umem_info *umem;
	void *bufs;
	int signal_fd;
	bool extra_stats;

	unsigned int num_socks;
	struct xsk_socket_info *xsks[MAX_SOCKS];
	__u8 pkt_data[MAX_PKT_SIZE];
	enum xsk_benchmark_type bench;
	bool rx;
	bool tx;
};

int xsk_validate_opts(const struct xsk_opts *opt);
struct xsk_ctx *xsk_ctx__create(const struct xsk_opts *opt,
				enum xsk_benchmark_type bench);
void xsk_ctx__destroy(struct xsk_ctx *ctx);
int xsk_stats_poller(struct xsk_ctx *ctx);
int xsk_start_bench(struct xsk_ctx *ctx, pthread_t *pt);

#endif /* XDPSOCK_H */
