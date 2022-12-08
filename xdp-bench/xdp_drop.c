// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
 */
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <xdp/libxdp.h>

#include "logging.h"

#include "xdp-bench.h"
#include "xdp_sample.h"
#include "xdp_drop.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_EXCEPTION_CNT | SAMPLE_DROP_OK;

DEFINE_SAMPLE_INIT(xdp_drop);

const struct drop_opts defaults_drop = { .mode = XDP_MODE_NATIVE,
					 .interval = 2 };

int do_drop(const void *cfg, __unused const char *pin_root_path)
{
	const struct drop_opts *opt = cfg;

	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	int ret = EXIT_FAIL_OPTION;
	struct xdp_drop *skel;

	if (opt->extended)
		sample_switch_mode();

	skel = xdp_drop__open();
	if (!skel) {
		pr_warn("Failed to xdp_drop__open: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel, opt->iface_in.ifname);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (opt->program_mode >= DROP_READ_DATA)
		skel->rodata->read_data = true;
	if (opt->program_mode >= DROP_SWAP_MACS)
		skel->rodata->swap_macs = true;
	if (opt->rxq_stats) {
		skel->rodata->rxq_stats = true;
		mask |= SAMPLE_RXQ_STATS;
	}

	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(skel->progs.xdp_drop_prog);
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	ret = xdp_program__attach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
	if (ret < 0) {
		pr_warn("Failed to attach XDP program: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = sample_init(skel, mask, 0, 0);
	if (ret < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}

	ret = EXIT_FAIL;

	printf("Dropping packets on %s (ifindex %d; driver %s)\n",
	       opt->iface_in.ifname, opt->iface_in.ifindex, get_driver_name(opt->iface_in.ifindex));

	ret = sample_run(opt->interval, NULL, NULL);
	if (ret < 0) {
		pr_warn("Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}
	ret = EXIT_OK;
end_detach:
	xdp_program__detach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
end_destroy:
	xdp_drop__destroy(skel);
end:
	sample_teardown();
	return ret;
}
