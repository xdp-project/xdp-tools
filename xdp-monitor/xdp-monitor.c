// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc. */
static const char *__doc__=
"XDP monitor tool, based on tracepoints\n";

static const char *__doc_err_only__=
"NOTICE: Only tracking XDP redirect errors\n"
"        Enable redirect success stats via '-s/--stats'\n"
"        (which comes with a per packet processing overhead)\n";

#define PROG_NAME "xdp-monitor"

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <locale.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

#include <xdp_sample.h>
#include "xdp_monitor.skel.h"
#include "params.h"
#include "util.h"
#include "logging.h"

static int mask = SAMPLE_REDIRECT_ERR_CNT | SAMPLE_CPUMAP_ENQUEUE_CNT |
		  SAMPLE_CPUMAP_KTHREAD_CNT | SAMPLE_EXCEPTION_CNT |
		  SAMPLE_DEVMAP_XMIT_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI;

DEFINE_SAMPLE_INIT(xdp_monitor);

static const struct monitoropt {
	bool stats;
	bool extended;
	__u32 interval;
} defaults_monitoropt = { .stats = false, .interval = 2 };

static struct prog_option xdpmonitor_options[] = {
	DEFINE_OPTION("interval", OPT_U32, struct monitoropt, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Polling interval (default 2)"),
	DEFINE_OPTION("stats", OPT_BOOL, struct monitoropt, stats,
		      .short_opt = 's',
		      .help = "Enable statistics for transmitted packets (not just errors)"),
	DEFINE_OPTION("extended", OPT_BOOL, struct monitoropt, extended,
		      .short_opt = 'e',
		      .help = "Start running in extended output mode (C^\\ to toggle)"),
	END_OPTIONS
};

int main(int argc, char **argv)
{
	int ret = EXIT_FAIL_OPTION;
	struct monitoropt cfg = {};
	struct xdp_monitor *skel;

	if (parse_cmdline_args(argc, argv, xdpmonitor_options, &cfg,
			       PROG_NAME, PROG_NAME, __doc__,
			       &defaults_monitoropt) != 0)
		return ret;

	/* If all the options are parsed ok, make sure we are root! */
	if (check_bpf_environ())
		return ret;

	skel = xdp_monitor__open();
	if (!skel) {
		pr_warn("Failed to xdp_monitor__open: %s\n",
			strerror(errno));
		return EXIT_FAIL_BPF;
	}

	ret = sample_init_pre_load(skel, NULL);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = xdp_monitor__load(skel);
	if (ret < 0) {
		pr_warn("Failed to xdp_monitor__load: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (cfg.stats)
		mask |= SAMPLE_REDIRECT_CNT;
	else
		printf("%s", __doc_err_only__);

	if (cfg.extended)
		sample_switch_mode();

	ret = sample_init(skel, mask, 0, 0);
	if (ret < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = sample_run(cfg.interval, NULL, NULL);
	if (ret < 0) {
		pr_warn("Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}
	ret = EXIT_OK;

end_destroy:
	xdp_monitor__destroy(skel);
	sample_teardown();
	return ret;
}
