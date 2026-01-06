// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <locale.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpsock.h"
#include "xdp_sample.h"
#include "logging.h"
#include "util.h"

#include "xdpsock.skel.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif

#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif

#define NUM_FRAMES (4 * 1024)
#define IS_EOP_DESC(options) (!((options) & XDP_PKT_CONTD))

#define DEBUG_HEXDUMP 0

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_VID__DEFAULT	1
#define VLAN_PRI__DEFAULT	0

#define NSEC_PER_SEC		1000000000UL
#define NSEC_PER_USEC		1000

#define SCHED_PRI__DEFAULT	0
#define STRERR_BUFSIZE          1024

#define POLL_TIMEOUT 1000

struct vlan_ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#define PKTGEN_MAGIC 0xbe9be955
struct pktgen_hdr {
	__be32 pgh_magic;
	__be32 seq_num;
	__be32 tv_sec;
	__be32 tv_usec;
};

struct xsk_ring_stats {
	unsigned long rx_frags;
	unsigned long rx_npkts;
	unsigned long tx_frags;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;
	unsigned long prev_rx_frags;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_frags;
	unsigned long prev_tx_npkts;
	unsigned long prev_rx_dropped_npkts;
	unsigned long prev_rx_invalid_npkts;
	unsigned long prev_tx_invalid_npkts;
	unsigned long prev_rx_full_npkts;
	unsigned long prev_rx_fill_empty_npkts;
	unsigned long prev_tx_empty_npkts;
};

struct xsk_driver_stats {
	unsigned long intrs;
	unsigned long prev_intrs;
};

struct xsk_app_stats {
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long copy_tx_sendtos;
	unsigned long tx_wakeup_sendtos;
	unsigned long opt_polls;
	unsigned long prev_rx_empty_polls;
	unsigned long prev_fill_fail_polls;
	unsigned long prev_copy_tx_sendtos;
	unsigned long prev_tx_wakeup_sendtos;
	unsigned long prev_opt_polls;
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	struct xsk_ring_stats ring_stats;
	struct xsk_app_stats app_stats;
	struct xsk_driver_stats drv_stats;
	__u32 outstanding_tx;
	bool copy_mode;
};

static unsigned long get_nsecs(clockid_t clock)
{
	struct timespec ts;

	clock_gettime(clock, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static int xsk_get_xdp_stats(int fd, struct xsk_socket_info *xsk)
{
	struct xdp_statistics stats;
	socklen_t optlen;
	int err;

	optlen = sizeof(stats);
	err = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &optlen);
	if (err)
		return err;

	if (optlen == sizeof(struct xdp_statistics)) {
		xsk->ring_stats.rx_dropped_npkts = stats.rx_dropped;
		xsk->ring_stats.rx_invalid_npkts = stats.rx_invalid_descs;
		xsk->ring_stats.tx_invalid_npkts = stats.tx_invalid_descs;
		xsk->ring_stats.rx_full_npkts = stats.rx_ring_full;
		xsk->ring_stats.rx_fill_empty_npkts = stats.rx_fill_ring_empty_descs;
		xsk->ring_stats.tx_empty_npkts = stats.tx_ring_empty_descs;
		return 0;
	}

	return -EINVAL;
}

static void dump_app_stats(const struct xsk_ctx *ctx, long dt, unsigned int i)
{
#define PPS(_now, _prev) ((_now - _prev) * 1000000000. / dt)

	char *fmt = "  %-18s %'14.0f calls/s\n";
	double rx_empty_polls_ps, fill_fail_polls_ps, copy_tx_sendtos_ps,
		tx_wakeup_sendtos_ps, opt_polls_ps;

	rx_empty_polls_ps    = PPS(ctx->xsks[i]->app_stats.rx_empty_polls,
				   ctx->xsks[i]->app_stats.prev_rx_empty_polls);
	fill_fail_polls_ps   = PPS(ctx->xsks[i]->app_stats.fill_fail_polls,
				   ctx->xsks[i]->app_stats.prev_fill_fail_polls);
	copy_tx_sendtos_ps   = PPS(ctx->xsks[i]->app_stats.copy_tx_sendtos,
				   ctx->xsks[i]->app_stats.prev_copy_tx_sendtos);
	tx_wakeup_sendtos_ps = PPS(ctx->xsks[i]->app_stats.tx_wakeup_sendtos,
				   ctx->xsks[i]->app_stats.prev_tx_wakeup_sendtos);
	opt_polls_ps	     = PPS(ctx->xsks[i]->app_stats.opt_polls,
				   ctx->xsks[i]->app_stats.prev_opt_polls);

	printf(fmt, "RX empty polls", rx_empty_polls_ps);
	printf(fmt, "Till fail polls", fill_fail_polls_ps);
	printf(fmt, "Copy tx sendtos", copy_tx_sendtos_ps);
	printf(fmt, "TX wakeup sendtos", tx_wakeup_sendtos_ps);
	printf(fmt, "Opt polls", opt_polls_ps);

	ctx->xsks[i]->app_stats.prev_rx_empty_polls = ctx->xsks[i]->app_stats.rx_empty_polls;
	ctx->xsks[i]->app_stats.prev_fill_fail_polls = ctx->xsks[i]->app_stats.fill_fail_polls;
	ctx->xsks[i]->app_stats.prev_copy_tx_sendtos = ctx->xsks[i]->app_stats.copy_tx_sendtos;
	ctx->xsks[i]->app_stats.prev_tx_wakeup_sendtos = ctx->xsks[i]->app_stats.tx_wakeup_sendtos;
	ctx->xsks[i]->app_stats.prev_opt_polls = ctx->xsks[i]->app_stats.opt_polls;
#undef PPS
}

static bool get_interrupt_number(struct xsk_ctx *ctx, const char *irq_string)
{
	FILE *f_int_proc;
	char line[4096];
	bool found = false;

	f_int_proc = fopen("/proc/interrupts", "r");
	if (f_int_proc == NULL) {
		printf("Failed to open /proc/interrupts.\n");
		return found;
	}

	while (!feof(f_int_proc) && !found) {
		/* Make sure to read a full line at a time */
		if (fgets(line, sizeof(line), f_int_proc) == NULL ||
				line[strlen(line) - 1] != '\n') {
			printf("Error reading from interrupts file\n");
			break;
		}

		/* Extract interrupt number from line */
		if (strstr(line, irq_string) != NULL) {
			ctx->irq_no = atoi(line);
			found = true;
			break;
		}
	}

	fclose(f_int_proc);

	return found;
}

static int get_irqs(const struct xsk_ctx *ctx)
{
	char count_path[PATH_MAX];
	FILE *f_count_proc;
	char line[4096];
	char *p = NULL;
	int ret;

	snprintf(count_path, sizeof(count_path),
		"/sys/kernel/irq/%i/per_cpu_count", ctx->irq_no);
	f_count_proc = fopen(count_path, "r");
	if (f_count_proc == NULL) {
		ret = -errno;
		pr_warn("Failed to open %s: %s\n", count_path, strerror(-ret));
		return ret;
	}

	if (fgets(line, sizeof(line), f_count_proc) == NULL ||
			line[strlen(line) - 1] != '\n') {
		pr_warn("Error reading from %s\n", count_path);
		ret = -ENOENT;
	} else {
		static const char com[2] = ",";
		char *token;

		ret = 0;
		token = strtok_r(line, com, &p);
		while (token != NULL) {
			/* sum up interrupts across all cores */
			ret += atoi(token);
			token = strtok_r(NULL, com, &p);
		}
	}

	fclose(f_count_proc);

	return ret;
}

static void dump_driver_stats(struct xsk_ctx *ctx, long dt)
{
#define PPS(_now, _prev) ((_now - _prev) * 1000000000. / dt)
	unsigned int i;

	for (i = 0; i < ctx->num_socks && ctx->xsks[i]; i++) {
		char *fmt = " %-18s %'14.0f intrs/s\n";
		double intrs_ps;
		int n_ints = get_irqs(ctx);

		if (n_ints < 0) {
			printf("error getting intr info for intr %i\n", ctx->irq_no);
			return;
		}
		ctx->xsks[i]->drv_stats.intrs = n_ints - ctx->irqs_at_init;

		intrs_ps = PPS(ctx->xsks[i]->drv_stats.intrs, ctx->xsks[i]->drv_stats.prev_intrs);

		printf(fmt, "IRQs", intrs_ps);

		ctx->xsks[i]->drv_stats.prev_intrs = ctx->xsks[i]->drv_stats.intrs;
		break;
	}
#undef PPS
}

static void dump_end_stats(struct xsk_ctx *ctx)
{
	__u64 total_rx_f = 0, total_tx_f = 0, total_rx = 0, total_tx = 0;
	unsigned int i;

	for (i = 0; i < ctx->num_socks && ctx->xsks[i]; i++) {
		total_rx += ctx->xsks[i]->ring_stats.rx_npkts;
		total_tx += ctx->xsks[i]->ring_stats.tx_npkts;
		total_rx_f += ctx->xsks[i]->ring_stats.rx_frags;
		total_tx_f += ctx->xsks[i]->ring_stats.tx_frags;
	}

	printf("\nTotals:\n");
	if (ctx->rx) {
		printf(" %-18s %'14" PRIu64 " pkts", "RX", (uint64_t)total_rx);
		if (ctx->opt.frags)
			printf(" %'14" PRIu64 " frags", (uint64_t)total_rx_f);
		printf("\n");
	}
	if (ctx->tx) {
		printf(" %-18s %'14" PRIu64 " pkts", "TX", (uint64_t)total_tx);
		if (ctx->opt.frags)
			printf(" %'14" PRIu64 " frags", (uint64_t)total_tx_f);
		printf("\n");
	}

	if (ctx->irq_no)
		printf(" %-18s %'14lu intrs", "IRQs", ctx->xsks[0]->drv_stats.intrs);

	for (i = 0; i < ctx->num_socks && ctx->xsks[i]; i++) {
		char *fmt = "  %-18s %'14lu pkts\n";
		printf("\n sock%d:\n", i);
		if (ctx->rx) {
			printf("  %-18s %'14lu pkts", "RX", ctx->xsks[i]->ring_stats.rx_npkts);
			if (ctx->opt.frags)
				printf(" %'14lu frags", ctx->xsks[i]->ring_stats.rx_frags);
			printf("\n");
		}
		if (ctx->tx) {
			printf("  %-18s %'14lu pkts", "TX", ctx->xsks[i]->ring_stats.tx_npkts);
			if (ctx->opt.frags)
				printf(" %'14lu frags", ctx->xsks[i]->ring_stats.tx_frags);
			printf("\n");
		}

		if (ctx->extra_stats) {
			printf("\n");
			printf(fmt, "RX dropped", ctx->xsks[i]->ring_stats.rx_dropped_npkts);
			printf(fmt, "RX invalid", ctx->xsks[i]->ring_stats.rx_invalid_npkts);
			printf(fmt, "TX invalid", ctx->xsks[i]->ring_stats.tx_invalid_npkts);
			printf(fmt, "RX queue full", ctx->xsks[i]->ring_stats.rx_full_npkts);
			printf(fmt, "Fill ring empty", ctx->xsks[i]->ring_stats.rx_fill_empty_npkts);
			printf(fmt, "TX ring empty", ctx->xsks[i]->ring_stats.tx_empty_npkts);
		}


		if (ctx->opt.app_stats) {
			printf("\n");
			char *fmt = "  %-18s %'14lu calls\n";
			printf(fmt, "RX empty polls", ctx->xsks[i]->app_stats.rx_empty_polls);
			printf(fmt, "Till fail polls", ctx->xsks[i]->app_stats.fill_fail_polls);
			printf(fmt, "Copy tx sendtos", ctx->xsks[i]->app_stats.copy_tx_sendtos);
			printf(fmt, "TX wakeup sendtos", ctx->xsks[i]->app_stats.tx_wakeup_sendtos);
			printf(fmt, "Opt polls", ctx->xsks[i]->app_stats.opt_polls);
		}
	}
}

static void dump_stats(struct xsk_ctx *ctx)
{
	__u64 total_rx_f = 0, prev_total_rx_f = 0, total_tx_f = 0, prev_total_tx_f = 0;
	__u64 total_rx = 0, prev_total_rx = 0, total_tx = 0, prev_total_tx = 0;
	unsigned long now = get_nsecs(ctx->opt.clock);
	long dt = now - ctx->prev_time;
	unsigned int i;
#define PPS(_now, _prev) ((_now - _prev) * 1000000000. / dt)

	ctx->prev_time = now;

	for (i = 0; i < ctx->num_socks && ctx->xsks[i]; i++) {
		total_rx += ctx->xsks[i]->ring_stats.rx_npkts;
		total_tx += ctx->xsks[i]->ring_stats.tx_npkts;
		total_rx_f += ctx->xsks[i]->ring_stats.rx_frags;
		total_tx_f += ctx->xsks[i]->ring_stats.tx_frags;
		prev_total_rx += ctx->xsks[i]->ring_stats.prev_rx_npkts;
		prev_total_tx += ctx->xsks[i]->ring_stats.prev_tx_npkts;
		prev_total_rx_f += ctx->xsks[i]->ring_stats.prev_rx_frags;
		prev_total_tx_f += ctx->xsks[i]->ring_stats.prev_tx_frags;
	}
	printf("%s:%d", ctx->opt.iface.ifname, ctx->opt.queue_idx);
	if (ctx->rx) {
		printf(" %'14.0f rx/s", PPS(total_rx, prev_total_rx));
		if (ctx->opt.frags)
			printf(" %'14.0f rx frag/s", PPS(total_rx_f, prev_total_rx_f));
	}
	if (ctx->tx) {
		printf(" %'14.0f xmit/s", PPS(total_tx, prev_total_tx));
		if (ctx->opt.frags)
			printf(" %'14.0f xmit frag/s", PPS(total_tx_f, prev_total_tx_f));
	}
	printf("\n");

	if (ctx->irq_no)
		dump_driver_stats(ctx, dt);

	for (i = 0; i < ctx->num_socks && ctx->xsks[i]; i++) {
		char *fmt =   "  %-18s %'14.0f %-6s\n";
		char *fmt_2 = "  %-18s %'14.0f %-6s %'14.0f %-6s\n";
		double rx_pps, rx_fps, tx_pps, tx_fps, dropped_pps,
			rx_invalid_pps, full_pps, fill_empty_pps,
			tx_invalid_pps, tx_empty_pps;
		__u64 rx_npkts = ctx->xsks[i]->ring_stats.rx_npkts;
		__u64 rx_frags = ctx->xsks[i]->ring_stats.rx_frags;
		__u64 tx_npkts = ctx->xsks[i]->ring_stats.tx_npkts;
		__u64 tx_frags = ctx->xsks[i]->ring_stats.tx_frags;

		rx_fps = PPS(rx_frags, ctx->xsks[i]->ring_stats.prev_rx_frags);
		tx_fps = PPS(tx_frags, ctx->xsks[i]->ring_stats.prev_tx_frags);

		rx_pps = PPS(rx_npkts, ctx->xsks[i]->ring_stats.prev_rx_npkts);
		tx_pps = PPS(tx_npkts, ctx->xsks[i]->ring_stats.prev_tx_npkts);

		ctx->xsks[i]->ring_stats.prev_rx_frags = rx_frags;
		ctx->xsks[i]->ring_stats.prev_tx_frags = tx_frags;
		ctx->xsks[i]->ring_stats.prev_rx_npkts = rx_npkts;
		ctx->xsks[i]->ring_stats.prev_tx_npkts = tx_npkts;

		if (ctx->num_socks > 1 || ctx->extra_stats || ctx->opt.app_stats) {
			printf(" sock%-14d", i);

			if (ctx->rx) {
				printf(" %'14.0f rx/s  ", rx_pps);
				if (ctx->opt.frags)
					printf(" %'14.0f rx frag/s", rx_fps);
			}
			if (ctx->tx) {
				printf(" %'14.0f xmit/s", tx_pps);
				if (ctx->opt.frags)
					printf(" %'14.0f xmit frag/s", tx_fps);
			}

			printf("\n");
		}

		if (ctx->extra_stats) {
			if (!xsk_get_xdp_stats(xsk_socket__fd(ctx->xsks[i]->xsk), ctx->xsks[i])) {
				dropped_pps    = PPS(ctx->xsks[i]->ring_stats.rx_dropped_npkts,
						     ctx->xsks[i]->ring_stats.prev_rx_dropped_npkts);
				rx_invalid_pps = PPS(ctx->xsks[i]->ring_stats.rx_invalid_npkts,
						     ctx->xsks[i]->ring_stats.prev_rx_invalid_npkts);
				tx_invalid_pps = PPS(ctx->xsks[i]->ring_stats.tx_invalid_npkts,
						     ctx->xsks[i]->ring_stats.prev_tx_invalid_npkts);
				full_pps       = PPS(ctx->xsks[i]->ring_stats.rx_full_npkts,
						     ctx->xsks[i]->ring_stats.prev_rx_full_npkts);
				fill_empty_pps = PPS(ctx->xsks[i]->ring_stats.rx_fill_empty_npkts,
						     ctx->xsks[i]->ring_stats.prev_rx_fill_empty_npkts);
				tx_empty_pps   = PPS(ctx->xsks[i]->ring_stats.tx_empty_npkts,
						     ctx->xsks[i]->ring_stats.prev_tx_empty_npkts);

				printf(fmt,   "Dropped",         dropped_pps,    "pkt/s");
				printf(fmt_2, "Invalid",         rx_invalid_pps, "rx/s",
				                                 tx_invalid_pps, "tx/s");
				printf(fmt,   "Queue full",      full_pps,       "rx/s");
				printf(fmt,   "Fill ring empty", fill_empty_pps, "pkt/s");
				printf(fmt,   "TX ring empty",   tx_empty_pps,   "pkt/s");

				ctx->xsks[i]->ring_stats.prev_rx_dropped_npkts =
					ctx->xsks[i]->ring_stats.rx_dropped_npkts;
				ctx->xsks[i]->ring_stats.prev_rx_invalid_npkts =
					ctx->xsks[i]->ring_stats.rx_invalid_npkts;
				ctx->xsks[i]->ring_stats.prev_tx_invalid_npkts =
					ctx->xsks[i]->ring_stats.tx_invalid_npkts;
				ctx->xsks[i]->ring_stats.prev_rx_full_npkts =
					ctx->xsks[i]->ring_stats.rx_full_npkts;
				ctx->xsks[i]->ring_stats.prev_rx_fill_empty_npkts =
					ctx->xsks[i]->ring_stats.rx_fill_empty_npkts;
				ctx->xsks[i]->ring_stats.prev_tx_empty_npkts =
					ctx->xsks[i]->ring_stats.tx_empty_npkts;
			} else {
				printf("%-18s\n", "Error retrieving extra stats");
			}
		}
		if (ctx->opt.app_stats) {
			printf("\n");
			dump_app_stats(ctx, dt, i);
		}

	}
#undef PPS
	if (ctx->opt.app_stats &&ctx->tx_cycle_ns) {
		printf(" %-18s period:%-10lu min:%-10lu ave:%-10lu max:%-10lu cycle:%-10lu\n",
		       "Cyclic TX", ctx->tx_cycle_ns, ctx->tx_cycle_diff_min,
		       (long)(ctx->tx_cycle_diff_ave / ctx->tx_cycle_cnt),
		       ctx->tx_cycle_diff_max, ctx->tx_cycle_cnt);
	}
}

static bool is_benchmark_done(struct xsk_ctx *ctx)
{
	if (ctx->duration > 0) {
		unsigned long dt = (get_nsecs(ctx->opt.clock) - ctx->start_time);

		if (dt >= ctx->duration)
			ctx->benchmark_done = true;
	}

	if (sample_immediate_exit())
		ctx->benchmark_done = true;

	return ctx->benchmark_done;
}

static int signal_cb(struct xsk_ctx *ctx)
{
	struct signalfd_siginfo si;
	int r;

	r = read(ctx->signal_fd, &si, sizeof(si));
	if (r < 0)
		return -errno;

	switch (si.ssi_signo) {
	case SIGQUIT:
		ctx->extra_stats = !ctx->extra_stats;
		printf("\n");
		break;
	default:
		printf("\n");
		return 1;
	}

	return 0;
}

int xsk_stats_poller(struct xsk_ctx *ctx)
{
	struct timespec ts = { ctx->opt.interval, 0 };
	struct itimerspec its = { ts, ts };
	struct pollfd pfd[2] = {};
	int timerfd, ret = 0;
	__u64 t;

	setlocale(LC_NUMERIC, "en_US.UTF-8");

	timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (timerfd < 0)
		return -errno;

	if (timerfd_settime(timerfd, 0, &its, NULL)) {
		ret = -errno;
		goto out;
	}

	pfd[0].fd = ctx->signal_fd;
	pfd[0].events = POLLIN;

	pfd[1].fd = timerfd;
	pfd[1].events = POLLIN;

	while (!is_benchmark_done(ctx)) {
		ret = poll(pfd, 2, -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			else
				goto out;
		}

		if (pfd[0].revents & POLLIN) {
			ret = signal_cb(ctx);
			if (ret) {
				dump_stats(ctx);
				break;
			}
		}

		if (pfd[1].revents & POLLIN) {
			ret = read(timerfd, &t, sizeof(t));
			if (ret < 0) {
				ret = -errno;
				goto out;
			}
			if (!ctx->opt.quiet)
				dump_stats(ctx);
		}
	}
	ret = 0;
out:
	ctx->benchmark_done = true;
	close(timerfd);
	return ret;
}

void xsk_ctx__destroy(struct xsk_ctx *ctx)
{
	struct xsk_umem *umem = ctx->xsks[0]->umem->umem;
	unsigned int i;

	dump_end_stats(ctx);
	for (i = 0; i < ctx->num_socks; i++)
		xsk_socket__delete(ctx->xsks[i]->xsk);
	(void)xsk_umem__delete(umem);

	if (ctx->xdp_prog) {
		xdp_program__detach(ctx->xdp_prog, ctx->opt.iface.ifindex,
				    ctx->opt.attach_mode, 0);
		xdp_program__close(ctx->xdp_prog);
	}

	close(ctx->signal_fd);
	munmap(ctx->bufs, NUM_FRAMES * ctx->opt.frame_size);
	free(ctx);
}

static void swap_mac_addresses(void *data)
{
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr tmp;

	tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = tmp;
}

static void hex_dump(void *pkt, size_t length, __u64 addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	if (!DEBUG_HEXDUMP)
		return;

	sprintf(buf, "addr=%" PRIu64, (uint64_t)addr);
	printf("length = %zu\n", length);
	printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
}

static void *memset32_htonl(void *dest, __u32 val, __u32 size)
{
	__u32 *ptr = (__u32 *)dest;
	__u32 i;

	val = htonl(val);

	for (i = 0; i < (size & (~0x3)); i += 4)
		ptr[i >> 2] = val;

	for (; i < size; i++)
		((char *)dest)[i] = ((char *)&val)[i & 3];

	return dest;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum(iph, ihl * 4);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
	__u32 sum = (__u32)csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline __u32 from64to32(__u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (__u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (__u32)sum;

	s += (__u32)saddr;
	s += (__u32)daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline __u16 udp_csum(__u32 saddr, __u32 daddr, __u32 len,
			     __u8 proto, __u16 *udp_pkt)
{
	__u32 csum = 0;
	__u32 cnt = 0;

	/* udp hdr and data */
	for (; cnt < len; cnt += 2)
		csum += udp_pkt[cnt >> 1];

	return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

#define ETH_FCS_SIZE 4

#define ETH_HDR_SIZE(opt) ((opt)->vlan_tag ? sizeof(struct vlan_ethhdr) : \
		      sizeof(struct ethhdr))
#define PKTGEN_HDR_SIZE(opt) ((opt)->timestamp ? sizeof(struct pktgen_hdr) : 0)
#define PKT_HDR_SIZE(opt) (ETH_HDR_SIZE(opt) + sizeof(struct iphdr) +	\
			   sizeof(struct udphdr) + PKTGEN_HDR_SIZE(opt))
#define PKTGEN_HDR_OFFSET(opt) (ETH_HDR_SIZE(opt) + sizeof(struct iphdr) + \
			   sizeof(struct udphdr))
#define PKTGEN_SIZE_MIN(opt) (PKTGEN_HDR_OFFSET(opt) + sizeof(struct pktgen_hdr) + \
			 ETH_FCS_SIZE)

#define PKT_SIZE(opt)		((opt)->tx_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE(opt)		(PKT_SIZE(opt) - ETH_HDR_SIZE(opt))
#define UDP_PKT_SIZE(opt)		(IP_PKT_SIZE(opt) - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE(opt)	(UDP_PKT_SIZE(opt) -			\
				 (sizeof(struct udphdr) + PKTGEN_HDR_SIZE(opt)))

static void gen_eth_hdr_data(struct xsk_ctx *ctx)
{
	struct pktgen_hdr *pktgen_hdr;
	struct udphdr *udp_hdr;
	struct iphdr *ip_hdr;

	if (ctx->opt.vlan_tag) {
		struct vlan_ethhdr *veth_hdr = (struct vlan_ethhdr *)ctx->pkt_data;
		__u16 vlan_tci = 0;

		udp_hdr = (struct udphdr *)(ctx->pkt_data +
					    sizeof(struct vlan_ethhdr) +
					    sizeof(struct iphdr));
		ip_hdr = (struct iphdr *)(ctx->pkt_data +
					  sizeof(struct vlan_ethhdr));
		pktgen_hdr = (struct pktgen_hdr *)(ctx->pkt_data +
						   sizeof(struct vlan_ethhdr) +
						   sizeof(struct iphdr) +
						   sizeof(struct udphdr));
		/* ethernet & VLAN header */
		memcpy(veth_hdr->h_dest, &ctx->opt.dst_mac, ETH_ALEN);
		memcpy(veth_hdr->h_source, &ctx->opt.src_mac, ETH_ALEN);
		veth_hdr->h_vlan_proto = htons(ETH_P_8021Q);
		vlan_tci = ctx->opt.vlan_id & VLAN_VID_MASK;
		vlan_tci |= (ctx->opt.vlan_pri << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK;
		veth_hdr->h_vlan_TCI = htons(vlan_tci);
		veth_hdr->h_vlan_encapsulated_proto = htons(ETH_P_IP);
	} else {
		struct ethhdr *eth_hdr = (struct ethhdr *)ctx->pkt_data;

		udp_hdr = (struct udphdr *)(ctx->pkt_data +
					    sizeof(struct ethhdr) +
					    sizeof(struct iphdr));
		ip_hdr = (struct iphdr *)(ctx->pkt_data +
					  sizeof(struct ethhdr));
		pktgen_hdr = (struct pktgen_hdr *)(ctx->pkt_data +
						   sizeof(struct ethhdr) +
						   sizeof(struct iphdr) +
						   sizeof(struct udphdr));
		/* ethernet header */
		memcpy(eth_hdr->h_dest, &ctx->opt.dst_mac, ETH_ALEN);
		memcpy(eth_hdr->h_source, &ctx->opt.src_mac, ETH_ALEN);
		eth_hdr->h_proto = htons(ETH_P_IP);
	}


	/* IP header */
	ip_hdr->version = IPVERSION;
	ip_hdr->ihl = 0x5; /* 20 byte header */
	ip_hdr->tos = 0x0;
	ip_hdr->tot_len = htons(IP_PKT_SIZE(&ctx->opt));
	ip_hdr->id = 0;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->protocol = IPPROTO_UDP;
	ip_hdr->saddr = htonl(0x0a0a0a10);
	ip_hdr->daddr = htonl(0x0a0a0a20);

	/* IP header checksum */
	ip_hdr->check = 0;
	ip_hdr->check = ip_fast_csum((const void *)ip_hdr, ip_hdr->ihl);

	/* UDP header */
	udp_hdr->source = htons(0x1000);
	udp_hdr->dest = htons(0x1000);
	udp_hdr->len = htons(UDP_PKT_SIZE(&ctx->opt));

	if (ctx->opt.timestamp)
		pktgen_hdr->pgh_magic = htonl(PKTGEN_MAGIC);

	/* UDP data */
	memset32_htonl(ctx->pkt_data + PKT_HDR_SIZE(&ctx->opt), ctx->opt.pkt_fill_pattern,
		       UDP_PKT_DATA_SIZE(&ctx->opt));

	/* UDP header checksum */
	udp_hdr->check = 0;
	udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, UDP_PKT_SIZE(&ctx->opt),
				  IPPROTO_UDP, (__u16 *)udp_hdr);
}

static void gen_eth_frames(struct xsk_ctx *ctx, struct xsk_umem_info *umem, __u32 frame_size)
{
	__u32 copy_len = frame_size;
	__u32 len = 0;
	unsigned int i;

	for (i = 0; i < NUM_FRAMES; i++) {
		__u64 addr = i * frame_size;

		if (!len) {
			len = PKT_SIZE(&ctx->opt);
			copy_len = frame_size;
		}

		if (len < frame_size)
			copy_len = len;

		memcpy(xsk_umem__get_data(umem->buffer, addr),
		       ctx->pkt_data + PKT_SIZE(&ctx->opt) - len, copy_len);

		len -= copy_len;
	}
}

static struct xsk_umem_info *xsk_configure_umem(void *buffer, __u64 size,
						__u32 frame_size, __u32 umem_flags)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = umem_flags
	};
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return ERR_PTR(-errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &cfg);
	if (ret) {
		free(umem);
		return ERR_PTR(ret);
	}

	umem->buffer = buffer;
	return umem;
}

static int xsk_populate_fill_ring(struct xsk_umem_info *umem, __u32 frame_size)
{
	int ret, i;
	__u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		return -ret;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			i * frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);

	return 0;
}

static struct xsk_socket_info *xsk_configure_socket(const struct xsk_opts *opt,
						    struct xsk_umem_info *umem,
						    bool rx, bool tx)
{
	__u32 xdp_bind_flags = opt->no_need_wakeup ? 0 : XDP_USE_NEED_WAKEUP;
	struct xsk_socket_config cfg = {};
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	if (opt->attach_mode == XDP_MODE_SKB)
		xdp_bind_flags |= XDP_COPY;
	xdp_bind_flags |= opt->copy_mode;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return ERR_PTR(-errno);

	xsk->umem = umem;
	xsk->copy_mode = !!(xdp_bind_flags & XDP_COPY);
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	if (opt->shared_umem || opt->frags)
		cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	else
		cfg.libxdp_flags = 0;
	if (opt->attach_mode == XDP_MODE_SKB)
		cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
	else
		cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
	cfg.bind_flags = xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;
	ret = xsk_socket__create(&xsk->xsk, opt->iface.ifname, opt->queue_idx,
				 umem->umem, rxr, txr, &cfg);
	if (ret)
		goto err;

	xsk->app_stats.rx_empty_polls = 0;
	xsk->app_stats.fill_fail_polls = 0;
	xsk->app_stats.copy_tx_sendtos = 0;
	xsk->app_stats.tx_wakeup_sendtos = 0;
	xsk->app_stats.opt_polls = 0;
	xsk->app_stats.prev_rx_empty_polls = 0;
	xsk->app_stats.prev_fill_fail_polls = 0;
	xsk->app_stats.prev_copy_tx_sendtos = 0;
	xsk->app_stats.prev_tx_wakeup_sendtos = 0;
	xsk->app_stats.prev_opt_polls = 0;

	return xsk;
err:
	free(xsk);
	return ERR_PTR(ret);
}

static int kick_tx(struct xsk_socket_info *xsk)
{
	int ret;
	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return 0;
	return -errno;
}

static inline int complete_tx_l2fwd(struct xsk_socket_info *xsk,
				    __u32 batch_size, bool busy_poll)
{
	struct xsk_umem_info *umem = xsk->umem;
	__u32 idx_cq = 0, idx_fq = 0;
	unsigned int rcvd;
	size_t ndescs;
	int ret;

	if (!xsk->outstanding_tx)
		return 0;

	/* In copy mode, Tx is driven by a syscall so we need to use e.g. sendto() to
	 * really send the packets. In zero-copy mode we do not have to do this, since Tx
	 * is driven by the NAPI loop. So as an optimization, we do not have to call
	 * sendto() all the time in zero-copy mode for l2fwd.
	 */
	if (xsk->copy_mode) {
		xsk->app_stats.copy_tx_sendtos++;
		ret = kick_tx(xsk);
		if (ret)
			return ret;
	}

	ndescs = min(xsk->outstanding_tx, batch_size);

	/* re-add completed Tx buffers */
	rcvd = xsk_ring_cons__peek(&umem->cq, ndescs, &idx_cq);
	if (rcvd > 0) {
		unsigned int i;
		int ret;

		ret = xsk_ring_prod__reserve(&umem->fq, rcvd, &idx_fq);
		while (ret != (int)rcvd) {
			if (ret < 0)
				return ret;
			if (busy_poll || xsk_ring_prod__needs_wakeup(&umem->fq)) {
				xsk->app_stats.fill_fail_polls++;
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			}
			ret = xsk_ring_prod__reserve(&umem->fq, rcvd, &idx_fq);
		}

		for (i = 0; i < rcvd; i++)
			*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) =
				*xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);

		xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
	return 0;
}

static inline void complete_tx_only(struct xsk_socket_info *xsk,
				    int batch_size, bool need_wakeup)
{
	unsigned int rcvd;
	__u32 idx;

	if (!xsk->outstanding_tx)
		return;

	if (!need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
		xsk->app_stats.tx_wakeup_sendtos++;
		kick_tx(xsk);
	}

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static int rx_drop(struct xsk_socket_info *xsk, __u32 batch_size, bool busy_poll)
{
	unsigned int rcvd, i, eop_cnt = 0;
	__u32 idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, batch_size, &idx_rx);
	if (!rcvd) {
		if (busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return 0;
	}

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while ((unsigned int)ret != rcvd) {
		if (ret < 0)
			return ret;
		if (busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.fill_fail_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		__u64 addr = desc->addr;
		__u32 len = desc->len;
		__u64 orig = xsk_umem__extract_addr(addr);
		eop_cnt += IS_EOP_DESC(desc->options);

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		hex_dump(pkt, len, addr);
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
	}

	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;

	return 0;
}

static void *xsk_rx_drop_all(void *arg)
{
	struct xsk_ctx *ctx = arg;
	struct pollfd fds[MAX_SOCKS] = {};
	unsigned int i;
	int ret;

	for (i = 0; i < ctx->num_socks; i++) {
		fds[i].fd = xsk_socket__fd(ctx->xsks[i]->xsk);
		fds[i].events = POLLIN;
	}

	while (!ctx->benchmark_done) {
		if (ctx->opt.use_poll) {
			for (i = 0; i < ctx->num_socks; i++)
				ctx->xsks[i]->app_stats.opt_polls++;
			ret = poll(fds, ctx->num_socks, ctx->poll_timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < ctx->num_socks; i++)
			rx_drop(ctx->xsks[i], ctx->opt.batch_size, ctx->opt.busy_poll);
	}
	return NULL;
}

static int tx_only(struct xsk_ctx *ctx, struct xsk_socket_info *xsk, __u32 *frame_nb,
		   int batch_size, unsigned long tx_ns)
{
	__u32 idx, tv_sec, tv_usec;
	int i;

	while (xsk_ring_prod__reserve(&xsk->tx, batch_size, &idx) <
	       (unsigned int)batch_size) {
		complete_tx_only(xsk, batch_size, !ctx->opt.no_need_wakeup);
		if (ctx->benchmark_done)
			return 0;
	}

	if (ctx->opt.timestamp) {
		tv_sec = (__u32)(tx_ns / NSEC_PER_SEC);
		tv_usec = (__u32)((tx_ns % NSEC_PER_SEC) / 1000);
	}

	for (i = 0; i < batch_size; ) {
		__u32 len = PKT_SIZE(&ctx->opt);

		do {
			struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx,
									  idx + i);
			tx_desc->addr = *frame_nb * ctx->opt.frame_size;
			if (len > ctx->opt.frame_size) {
				tx_desc->len = ctx->opt.frame_size;
				tx_desc->options = XDP_PKT_CONTD;
			} else {
				tx_desc->len = len;
				tx_desc->options = 0;
				xsk->ring_stats.tx_npkts++;
			}
			len -= tx_desc->len;
			*frame_nb = (*frame_nb + 1) % NUM_FRAMES;
			i++;

			if (ctx->opt.timestamp) {
				struct pktgen_hdr *pktgen_hdr;
				__u64 addr = tx_desc->addr;
				char *pkt;

				pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
				pktgen_hdr = (struct pktgen_hdr *)(pkt + PKTGEN_HDR_OFFSET(&ctx->opt));

				pktgen_hdr->seq_num = htonl(ctx->sequence++);
				pktgen_hdr->tv_sec = htonl(tv_sec);
				pktgen_hdr->tv_usec = htonl(tv_usec);

				hex_dump(pkt, PKT_SIZE(&ctx->opt), addr);
			}
		} while (len);
	}

	xsk_ring_prod__submit(&xsk->tx, batch_size);
	xsk->outstanding_tx += batch_size;
	xsk->ring_stats.tx_frags += batch_size;
	complete_tx_only(xsk, batch_size, !ctx->opt.no_need_wakeup);

	return batch_size / ctx->frames_per_pkt;
}

static inline int get_batch_size(const struct xsk_ctx *ctx, int pkt_cnt)
{
	if (!ctx->opt.pkt_count)
		return ctx->opt.batch_size * ctx->frames_per_pkt;

	if (pkt_cnt + ctx->opt.batch_size <= ctx->opt.pkt_count)
		return ctx->opt.batch_size * ctx->frames_per_pkt;

	return (ctx->opt.pkt_count - pkt_cnt) * ctx->frames_per_pkt;
}

static void complete_tx_only_all(struct xsk_ctx *ctx)
{
	bool pending;
	unsigned int i;

	do {
		pending = false;
		for (i = 0; i < ctx->num_socks; i++) {

			if (ctx->xsks[i]->outstanding_tx) {
				complete_tx_only(ctx->xsks[i], ctx->opt.batch_size, !ctx->opt.no_need_wakeup);
				pending = !!ctx->xsks[i]->outstanding_tx;
			}
		}
		sleep(1);
	} while (pending && ctx->retries-- > 0);
}

static void *xsk_tx_only_all(void *arg)
{
	struct xsk_ctx *ctx = arg;
	struct pollfd fds[MAX_SOCKS] = {};
	__u32 frame_nb[MAX_SOCKS] = {};
	unsigned long next_tx_ns = 0;
	unsigned int pkt_cnt = 0, i;
	int ret;

	for (i = 0; i < ctx->num_socks; i++) {
		fds[0].fd = xsk_socket__fd(ctx->xsks[i]->xsk);
		fds[0].events = POLLOUT;
	}

	if (ctx->tx_cycle_ns) {
		/* Align Tx time to micro-second boundary */
		next_tx_ns = (get_nsecs(ctx->opt.clock) / NSEC_PER_USEC + 1) * NSEC_PER_USEC;
		next_tx_ns += ctx->tx_cycle_ns;

		/* Initialize periodic Tx scheduling variance */
		ctx->tx_cycle_diff_min = 1000000000;
		ctx->tx_cycle_diff_max = 0;
		ctx->tx_cycle_diff_ave = 0.0;
	}

	while (!ctx->benchmark_done &&
	       ((ctx->opt.pkt_count && pkt_cnt < ctx->opt.pkt_count) || !ctx->opt.pkt_count)) {
		int batch_size = get_batch_size(ctx, pkt_cnt);
		unsigned long tx_ns = 0;
		struct timespec next;
		int tx_cnt = 0;
		long diff;
		int err;

		if (ctx->opt.use_poll) {
			for (i = 0; i < ctx->num_socks; i++)
				ctx->xsks[i]->app_stats.opt_polls++;
			ret = poll(fds, ctx->num_socks, ctx->poll_timeout);
			if (ret <= 0)
				continue;

			if (!(fds[0].revents & POLLOUT))
				continue;
		}

		if (ctx->tx_cycle_ns) {
			next.tv_sec = next_tx_ns / NSEC_PER_SEC;
			next.tv_nsec = next_tx_ns % NSEC_PER_SEC;
			err = clock_nanosleep(ctx->opt.clock, TIMER_ABSTIME, &next, NULL);
			if (err) {
				if (err != EINTR)
					pr_warn("clock_nanosleep failed. Err:%d errno:%d\n",
						err, errno);
				return ERR_PTR(err);
			}

			/* Measure periodic Tx scheduling variance */
			tx_ns = get_nsecs(ctx->opt.clock);
			diff = tx_ns - next_tx_ns;
			if (diff < ctx->tx_cycle_diff_min)
				ctx->tx_cycle_diff_min = diff;

			if (diff > ctx->tx_cycle_diff_max)
				ctx->tx_cycle_diff_max = diff;

			ctx->tx_cycle_diff_ave += (double)diff;
			ctx->tx_cycle_cnt++;
		} else if (ctx->opt.timestamp) {
			tx_ns = get_nsecs(ctx->opt.clock);
		}

		for (i = 0; i < ctx->num_socks; i++)
			tx_cnt += tx_only(ctx, ctx->xsks[i], &frame_nb[i], batch_size, tx_ns);

		pkt_cnt += tx_cnt;

		if (ctx->tx_cycle_ns)
			next_tx_ns += ctx->tx_cycle_ns;
	}

	if (ctx->opt.pkt_count)
		complete_tx_only_all(ctx);

	return NULL;
}

static int l2fwd(struct xsk_ctx *ctx, struct xsk_socket_info *xsk)
{
	__u32 idx_rx = 0, idx_tx = 0, frags_done = 0;
	unsigned int rcvd, i, eop_cnt = 0;
	static __u32 nb_frags;
	int ret;

	complete_tx_l2fwd(xsk, ctx->opt.batch_size, ctx->opt.busy_poll);

	rcvd = xsk_ring_cons__peek(&xsk->rx, ctx->opt.batch_size, &idx_rx);
	if (!rcvd) {
		if (ctx->opt.busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return 0;
	}

	ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
	while ((unsigned int)ret != rcvd) {
		if (ret < 0)
			return ret;
		complete_tx_l2fwd(xsk, ctx->opt.batch_size, ctx->opt.busy_poll);
		if (ctx->opt.busy_poll || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
			xsk->app_stats.tx_wakeup_sendtos++;
			ret = kick_tx(xsk);
			if (ret)
				return ret;
		}
		ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
	}

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		bool eop = IS_EOP_DESC(desc->options);
		__u64 addr = desc->addr;
		__u32 len = desc->len;
		__u64 orig = addr;

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		if (!nb_frags++)
			swap_mac_addresses(pkt);

		hex_dump(pkt, len, addr);

		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++);

		tx_desc->options = eop ? 0 : XDP_PKT_CONTD;
		tx_desc->addr = orig;
		tx_desc->len = len;

		if (eop) {
			frags_done += nb_frags;
			nb_frags = 0;
			eop_cnt++;
		}
	}

	xsk_ring_prod__submit(&xsk->tx, frags_done);
	xsk_ring_cons__release(&xsk->rx, frags_done);

	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.tx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;
	xsk->ring_stats.tx_frags += rcvd;
	xsk->outstanding_tx += frags_done;

	return 0;
}

void *xsk_l2fwd_all(void *arg)
{
	struct xsk_ctx *ctx = arg;
	struct pollfd fds[MAX_SOCKS] = {};
	unsigned int i;
	int ret;

	while (!ctx->benchmark_done) {
		if (ctx->opt.use_poll) {
			for (i = 0; i < ctx->num_socks; i++) {
				fds[i].fd = xsk_socket__fd(ctx->xsks[i]->xsk);
				fds[i].events = POLLOUT | POLLIN;
				ctx->xsks[i]->app_stats.opt_polls++;
			}
			ret = poll(fds, ctx->num_socks, ctx->poll_timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < ctx->num_socks; i++)
			l2fwd(ctx, ctx->xsks[i]);
	}
	return NULL;
}

static struct xdp_program *load_xdp_program(struct xsk_ctx *ctx,
					    const struct xsk_opts *opt,
					    bool populate_map)
{
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts,
			    .prog_name = "xdp_sock_prog");
	struct xdp_program *xdp_prog = NULL, *ret_prog;
	char errmsg[STRERR_BUFSIZE];
	struct xdpsock *skel;
	unsigned int i;
	int err;

	skel = xdpsock__open();
	if (!skel) {
		err = -errno;
		pr_warn("Failed to load skeleton: %s\n", strerror(-err));
		goto err;
	}

	opts.obj = skel->obj;
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		err = -errno;
		pr_warn("Failed to create XDP program: %s\n", strerror(-err));
		goto err;
	}

	/* we can't set this from the program section because libbpf won't let
         * us turn it back off if we do. So set it here to allow the automatic
         * logic for turning off the flag in libxdp to work
         */
        xdp_program__set_xdp_frags_support(xdp_prog, true);

	err = xdp_program__attach(xdp_prog, opt->iface.ifindex, opt->attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("ERROR: attaching program failed: %s\n", errmsg);
		goto err;
	}

	if (populate_map) {
		skel->bss->num_socks = ctx->num_socks;

		for (i = 0; i < ctx->num_socks; i++) {
			int fd = xsk_socket__fd(ctx->xsks[i]->xsk);
			int key = i;

			err = bpf_map_update_elem(
				bpf_map__fd(skel->maps.xsks_map),
				&key, &fd, 0);
			if (err) {
				pr_warn("ERROR: bpf_map_update_elem %d\n", i);
				goto err;
			}
		}
	}

	/* Clone the xdp_prog before returning to avoid having a dangling
	 * reference to the skeleton.
	 */
	ret_prog = xdp_program__clone(xdp_prog, 0);
	if (!ret_prog) {
		err = -errno;
		pr_warn("Couldn't clone xdp_program: %s\n", strerror(-err));
		goto err;
	}
	xdp_program__close(xdp_prog);
	xdpsock__destroy(skel);
	return ret_prog;
err:
	xdp_program__close(xdp_prog);
	xdpsock__destroy(skel);
	return ERR_PTR(err);
}

static int apply_busy_poll_opts(struct xsk_socket *xsk, __u32 batch_size)
{
	int sock_opt;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		return -errno;

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		return -errno;

	sock_opt = batch_size;
	if (setsockopt(xsk_socket__fd(xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		return -errno;

	return 0;
}

bool xsk_probe_busy_poll(void)
{
	struct xsk_socket_config cfg = {
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
	};
	unsigned int mmap_flags = 0, umem_flags = 0;
	__u32 frame_size = 4096, batch_size = 64;
	struct xsk_umem_info *umem = NULL;
	struct xsk_socket *xsk = NULL;
	struct xsk_ring_cons rx;
	void *bufs;
	int ret;

	bufs = mmap(NULL, NUM_FRAMES * frame_size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | mmap_flags, -1, 0);
	if (bufs == MAP_FAILED) {
		ret = -errno;
		pr_debug("Failed to mmap: %d\n", ret);
		goto out;
	}

	umem = xsk_configure_umem(bufs, NUM_FRAMES * frame_size,
				  frame_size, umem_flags);
	if (IS_ERR(umem)) {
		ret = PTR_ERR(umem);
		pr_debug("Failed to configure umem: %d\n", ret);
		umem = NULL;
		goto out;
	}

	ret = xsk_socket__create(&xsk, "lo", 0, umem->umem, &rx, NULL, &cfg);
	if (ret) {
		pr_debug("Failed to create socket: %d\n", ret);
		goto out;
	}

	ret = apply_busy_poll_opts(xsk, batch_size);
	pr_debug("Apply busy poll opts returned %d\n", ret);

out:
	xsk_socket__delete(xsk);
	if (umem) {
		xsk_umem__delete(umem->umem);
		free(umem);
	}
	munmap(bufs, NUM_FRAMES * frame_size);

	return !ret;
}

static int xsk_set_sched_priority(enum xsk_sched_policy sched_policy,
				  unsigned int sched_prio)
{
	struct sched_param schparam = {
		.sched_priority = sched_prio,
	};
	int ret;

	/* Configure sched priority for better wake-up accuracy */
	ret = sched_setscheduler(0, sched_policy, &schparam);
	if (ret)
		pr_warn("Error(%d) in setting priority(%d): %s\n",
			errno, sched_prio, strerror(errno));

	return ret;
}

struct xsk_ctx *xsk_ctx__create(const struct xsk_opts *opt, enum xsk_benchmark_type bench)
{
	unsigned int mmap_flags = 0, umem_flags = 0, num_xsks = 1, i;
	struct xsk_umem_info *umem = NULL;
	bool rx = false, tx = false;
	struct xsk_ctx *ctx;
	int ret = -ENOMEM;
	sigset_t st;
	void *bufs;

	switch (bench) {
	case XSK_BENCH_RXDROP:
		rx = true;
		break;
	case XSK_BENCH_TXONLY:
		tx = true;
		break;
	case XSK_BENCH_L2FWD:
		rx = true;
		tx = true;
		break;
	}

	if (opt->unaligned) {
		mmap_flags = MAP_HUGETLB;
		umem_flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
	}

	if (opt->shared_umem)
		num_xsks = MAX_SOCKS;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	bufs = mmap(NULL, NUM_FRAMES * opt->frame_size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | mmap_flags, -1, 0);
	if (bufs == MAP_FAILED) {
		pr_warn("ERROR: mmap failed\n");
		goto err;
	}

	/* Create sockets... */
	umem = xsk_configure_umem(bufs, NUM_FRAMES * opt->frame_size,
				  opt->frame_size, umem_flags);
	if (IS_ERR(umem)) {
		ret = PTR_ERR(umem);
		umem = NULL;
		goto err;
	}

	if (rx) {
		ret = xsk_populate_fill_ring(umem, opt->frame_size);
		if (ret)
			goto err;
	}

	for (i = 0; i < num_xsks; i++) {
		struct xsk_socket_info *xsk = xsk_configure_socket(opt, umem, rx, tx);
		if (IS_ERR(xsk)) {
			ret = PTR_ERR(xsk);
			goto err;
		}
		ctx->xsks[ctx->num_socks++] = xsk;
	}

	if (opt->busy_poll) {
		for (i = 0; i < num_xsks; i++) {
			ret = apply_busy_poll_opts(ctx->xsks[i]->xsk, opt->batch_size);
			if (ret) {
				pr_warn("ERROR: Couldn't apply busy poll options: %s\n",
					strerror(-ret));
				goto err;
			}
		}
	}

	if (opt->irq_string) {
		ret = -ENOENT;
		if (get_interrupt_number(ctx, opt->irq_string))
			ret = get_irqs(ctx);
		if (ret < 0) {
			pr_warn("ERROR: Failed to get irqs for %s\n", opt->irq_string);
			goto err;
		}
		ctx->irqs_at_init = ret;
	}

	ret = xsk_set_sched_priority(opt->sched_policy, opt->sched_prio);
	if (ret)
		goto err;

	memcpy((void *)&ctx->opt, opt, sizeof(ctx->opt));

	if (bench == XSK_BENCH_TXONLY) {
		gen_eth_hdr_data(ctx);
		gen_eth_frames(ctx, umem, opt->frame_size);
	}
	ctx->frames_per_pkt = (opt->tx_pkt_size - 1) / XSK_UMEM__DEFAULT_FRAME_SIZE + 1;

	if (opt->shared_umem || opt->frags) {
		struct xdp_program *xdp_prog = load_xdp_program(ctx, opt, rx);
		if (IS_ERR(xdp_prog)) {
			ret = PTR_ERR(xdp_prog);
			goto err;
		}
		ctx->xdp_prog = xdp_prog;
	}

	sigemptyset(&st);
	sigaddset(&st, SIGQUIT);
	sigaddset(&st, SIGINT);
	sigaddset(&st, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &st, NULL) < 0) {
		ret = -errno;
		goto err;
	}

	ctx->signal_fd = signalfd(-1, &st, SFD_CLOEXEC | SFD_NONBLOCK);
	if (ctx->signal_fd < 0) {
		ret = -errno;
		goto err;
	}

	ctx->bufs = bufs;
	ctx->umem = umem;
	ctx->bench = bench;

	ctx->prev_time = ctx->start_time = get_nsecs(ctx->opt.clock);
	ctx->tx_cycle_ns = opt->tx_cycle_us * NSEC_PER_USEC;
	ctx->poll_timeout = POLL_TIMEOUT;
	ctx->duration = opt->duration * NSEC_PER_SEC;
	ctx->retries = opt->retries;
	ctx->extra_stats = opt->extra_stats;
	ctx->rx = rx;
	ctx->tx = tx;
	return ctx;

err:
	if (ctx->xdp_prog) {
		xdp_program__detach(ctx->xdp_prog, ctx->opt.iface.ifindex,
				    ctx->opt.attach_mode, 0);
		xdp_program__close(ctx->xdp_prog);
	}
	for (i = 0; i < ctx->num_socks; i++) {
		xsk_socket__delete(ctx->xsks[i]->xsk);
		free(ctx->xsks[i]);
	}
	free(umem);
	munmap(bufs, NUM_FRAMES * opt->frame_size);
	free(ctx);
	return ERR_PTR(ret);
}

int xsk_start_bench(struct xsk_ctx *ctx, pthread_t *pt)
{
	switch (ctx->bench) {
	case XSK_BENCH_RXDROP:
		return pthread_create(pt, NULL, xsk_rx_drop_all, ctx);
	case XSK_BENCH_L2FWD:
		return pthread_create(pt, NULL, xsk_l2fwd_all, ctx);
	case XSK_BENCH_TXONLY:
		return pthread_create(pt, NULL, xsk_tx_only_all, ctx);
	default:
		return -EINVAL;
	}
}

int xsk_validate_opts(const struct xsk_opts *opt)
{
	if (opt->attach_mode == XDP_MODE_SKB && opt->copy_mode == XSK_COPY_ZEROCOPY) {
		pr_warn("Can't use zero-copy and skb mode together.\n");
		return -EINVAL;
	}

	if (!opt->unaligned && opt->frame_size & (opt->frame_size -1)) {
		pr_warn("Frame size %u is not a power of two.\n", opt->frame_size);
		return -EINVAL;
	}

	if (opt->use_poll && opt->tx_cycle_us) {
		pr_warn("Error: --poll and --tx-cycles are both set\n");
		return -EINVAL;
	}
	if (opt->timestamp && opt->tx_pkt_size < PKTGEN_SIZE_MIN(opt)) {
		pr_warn("TX packet size %d less than minimum %lu bytes when timestamps are enabled\n",
			opt->tx_pkt_size, PKTGEN_SIZE_MIN(opt));
		return -EINVAL;
	}
	if (opt->tx_pkt_size > MAX_PKT_SIZE || opt->tx_pkt_size < MIN_PKT_SIZE) {
		pr_warn("Invalid packet size %d (min %d max %x)\n",
			opt->tx_pkt_size, MIN_PKT_SIZE, MAX_PKT_SIZE);
		return -EINVAL;
	}

	return 0;
}
