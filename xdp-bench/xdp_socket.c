#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <xdp/libxdp.h>

#include "logging.h"
#include "xdp-bench.h"
#include "xdp_sample.h"

const struct xsk_opts defaults_xsk = {
	.attach_mode = XDP_MODE_NATIVE,
	.interval = 2,
	.retries = 3,
	.frame_size = 4096,
	.batch_size = 64,
	.tx_pkt_size = 64,
	.sched_policy = XSK_SCHED_OTHER,
	.clock = XSK_CLOCK_MONOTONIC,
};


static int do_xsk(const struct xsk_opts *opt,
		  enum xsk_benchmark_type bench)
{
	struct xsk_ctx *ctx;
	pthread_t pt;
	int ret;

	ret = xsk_validate_opts(opt);
	if (ret)
		return ret;

	ctx = xsk_ctx__create(opt, bench);
	ret = libxdp_get_error(ctx);
	if (ret)
		return ret;

	pr_info("%s packets on %s (ifindex %d; queue %d; driver %s) using AF_XDP sockets\n",
		bench == XSK_BENCH_RXDROP ? "Dropping" : "Hairpinning",
		opt->iface.ifname, opt->iface.ifindex, opt->queue_idx, get_driver_name(opt->iface.ifindex));

	ret = xsk_start_bench(ctx, &pt);
	if (ret)
		goto out;

	ret = xsk_stats_poller(ctx);
	pthread_join(pt, NULL);

out:
	xsk_ctx__destroy(ctx);
	return ret;
}

int do_xsk_drop(const void *cfg, __unused const char *pin_root_path)
{
	const struct xsk_opts *opt = cfg;

	return do_xsk(opt, XSK_BENCH_RXDROP);
}

int do_xsk_tx(const void *cfg, __unused const char *pin_root_path)
{
	const struct xsk_opts *opt = cfg;

	return do_xsk(opt, XSK_BENCH_L2FWD);
}
