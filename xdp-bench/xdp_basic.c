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
#include "xdp_basic.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_EXCEPTION_CNT;

DEFINE_SAMPLE_INIT(xdp_basic);

const struct basic_opts defaults_drop = { .mode = XDP_MODE_NATIVE,
					  .interval = 2 };
const struct basic_opts defaults_pass = { .mode = XDP_MODE_NATIVE,
					  .interval = 2 };
const struct basic_opts defaults_tx = { .mode = XDP_MODE_NATIVE,
					 .interval = 2,
					 .program_mode = BASIC_SWAP_MACS };

static int do_basic(const struct basic_opts *opt, enum xdp_action action)
{
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	struct bpf_program *prog = NULL;
	int ret = EXIT_FAIL_OPTION;
	struct xdp_basic *skel;

	if (opt->extended)
		sample_switch_mode();

	skel = xdp_basic__open();
	if (!skel) {
		pr_warn("Failed to xdp_basic__open: %s\n", strerror(errno));
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

	if (opt->rxq_stats) {
		skel->rodata->rxq_stats = true;
		mask |= SAMPLE_RXQ_STATS;
	}

	if (opt->load_mode == BASIC_LOAD_BYTES && opt->program_mode != BASIC_PARSE_IPHDR) {
		pr_warn("Setting '-l load-bytes' only works with '-p parse-ip'\n");
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	/* Make sure we only load the one XDP program we are interested in */
	while ((prog = bpf_object__next_program(skel->obj, prog)) != NULL)
		if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP &&
		    bpf_program__expected_attach_type(prog) == BPF_XDP)
			bpf_program__set_autoload(prog, false);

	switch (opt->program_mode) {
	case BASIC_NO_TOUCH:
		opts.prog_name = "xdp_basic_prog";
		break;
	case BASIC_READ_DATA:
		opts.prog_name = "xdp_read_data_prog";
		break;
	case BASIC_PARSE_IPHDR:
		opts.prog_name = (opt->load_mode == BASIC_LOAD_BYTES) ? "xdp_parse_load_bytes_prog" : "xdp_parse_prog";
		break;
	case BASIC_SWAP_MACS:
		opts.prog_name = "xdp_swap_macs_prog";
		break;
	}

	opts.obj = skel->obj;
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	/* We always set the frags support bit: nothing the program does is
	 * incompatible with multibuf, and it's perfectly fine to load a program
	 * with frags support on an interface with a small MTU. We don't risk
	 * setting any flags the kernel will balk at, either, since libxdp will
	 * do the feature probing for us and skip the flag if the kernel doesn't
	 * support it.
	 *
	 * The function below returns EOPNOTSUPP it libbpf is too old to support
	 * setting the flags, but we just ignore that, since in such a case the
	 * best we can do is just attempt to run without the frags support.
	 */
	xdp_program__set_xdp_frags_support(xdp_prog, true);

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
		action == XDP_DROP ? "Dropping" : action == XDP_TX ? "Hairpinning (XDP_TX)" : "Passing",
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
	xdp_basic__destroy(skel);
end:
	sample_teardown();
	return ret;
}

int do_drop(const void *cfg, __unused const char *pin_root_path)
{
	const struct basic_opts *opt = cfg;

	return do_basic(opt, XDP_DROP);
}

int do_pass(const void *cfg, __unused const char *pin_root_path)
{
	const struct basic_opts *opt = cfg;

	return do_basic(opt, XDP_PASS);
}

int do_tx(const void *cfg, __unused const char *pin_root_path)
{
	const struct basic_opts *opt = cfg;

	return do_basic(opt, XDP_TX);
}
