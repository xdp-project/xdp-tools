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
#include "xdp_droptx.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_EXCEPTION_CNT;

DEFINE_SAMPLE_INIT(xdp_droptx);
#define BPF_F_XDP_DEV_BOUND_ONLY	(1U << 6)

const struct droptx_opts defaults_drop = { .mode = XDP_MODE_NATIVE,
					     .interval = 2 };
const struct droptx_opts defaults_tx = { .mode = XDP_MODE_NATIVE,
					 .interval = 2,
					 .program_mode = DROPTX_SWAP_MACS };

static int do_droptx(const struct droptx_opts *opt, enum xdp_action action)
{
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	int ret = EXIT_FAIL_OPTION;
	struct xdp_droptx *skel;

	if (opt->extended)
		sample_switch_mode();

	skel = xdp_droptx__open();
	if (!skel) {
		pr_warn("Failed to xdp_droptx__open: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel, opt->iface_in.ifname);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	skel->rodata->action = action;
	if (action == XDP_DROP)
		mask |= SAMPLE_DROP_OK;

	if (opt->program_mode >= DROPTX_READ_DATA)
		skel->rodata->read_data = true;
	if (opt->program_mode >= DROPTX_SWAP_MACS)
		skel->rodata->swap_macs = true;
	if (opt->read_hw_meta) {
		skel->rodata->read_hw_meta = true;
		bpf_program__set_flags(skel->progs.xdp_droptx_prog,
				       BPF_F_XDP_DEV_BOUND_ONLY);
		bpf_program__set_ifindex(skel->progs.xdp_droptx_prog,
					 opt->iface_in.ifindex);
	}
	if (opt->rxq_stats) {
		skel->rodata->rxq_stats = true;
		mask |= SAMPLE_RXQ_STATS;
	}

	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(skel->progs.xdp_droptx_prog);
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

	pr_info("%s packets on %s (ifindex %d; driver %s)\n",
		action == XDP_DROP ? "Dropping" : "Hairpinning (XDP_TX)",
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
	xdp_droptx__destroy(skel);
end:
	sample_teardown();
	return ret;
}

int do_drop(const void *cfg, __unused const char *pin_root_path)
{
	const struct droptx_opts *opt = cfg;

	return do_droptx(opt, XDP_DROP);
}

int do_tx(const void *cfg, __unused const char *pin_root_path)
{
	const struct droptx_opts *opt = cfg;

	return do_droptx(opt, XDP_TX);
}
