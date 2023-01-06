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
#include "xdp_redirect_basic.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI;

DEFINE_SAMPLE_INIT(xdp_redirect_basic);

const struct redirect_opts defaults_redirect_basic = { .mode = XDP_MODE_NATIVE,
						    .interval = 2 };

int do_redirect_basic(const void *cfg, __unused const char *pin_root_path)
{
	const struct redirect_opts *opt = cfg;

	struct xdp_program *xdp_prog = NULL, *dummy_prog = NULL;
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_redirect_basic *skel;
	char str[2 * IF_NAMESIZE + 1];
	int ret = EXIT_FAIL_OPTION;

	if (opt->extended)
		sample_switch_mode();

	if (opt->mode == XDP_MODE_SKB)
		/* devmap_xmit tracepoint not available */
		mask &= ~(SAMPLE_DEVMAP_XMIT_CNT |
			  SAMPLE_DEVMAP_XMIT_CNT_MULTI);

	if (opt->stats)
		mask |= SAMPLE_REDIRECT_CNT;


	skel = xdp_redirect_basic__open();
	if (!skel) {
		pr_warn("Failed to xdp_redirect_basic__open: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel, opt->iface_in.ifname);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	skel->rodata->from_match[0] = opt->iface_in.ifindex;
	skel->rodata->to_match[0] = opt->iface_out.ifindex;
	skel->rodata->ifindex_out = opt->iface_out.ifindex;

	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(skel->progs.xdp_redirect_basic_prog);
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

	ret = sample_init(skel, mask, opt->iface_in.ifindex, opt->iface_out.ifindex);
	if (ret < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}

	opts.obj = NULL;
	opts.prog_name = "xdp_pass";
	opts.find_filename = "xdp-dispatcher.o";
	dummy_prog = xdp_program__create(&opts);
	if (!dummy_prog) {
		pr_warn("Failed to load dummy program: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_detach;
	}

	ret = xdp_program__attach(dummy_prog, opt->iface_out.ifindex, opt->mode, 0);
	if (ret < 0) {
		pr_warn("Failed to attach dummy program: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_detach;
	}

	ret = EXIT_FAIL;

	safe_strncpy(str, get_driver_name(opt->iface_in.ifindex), sizeof(str));
	pr_info("Redirecting from %s (ifindex %d; driver %s) to %s (ifindex %d; driver %s)\n",
		opt->iface_in.ifname, opt->iface_in.ifindex, str,
		opt->iface_out.ifname, opt->iface_out.ifindex, get_driver_name(opt->iface_out.ifindex));

	ret = sample_run(opt->interval, NULL, NULL);
	if (ret < 0) {
		pr_warn("Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}
	ret = EXIT_OK;
end_detach:
	if (dummy_prog)
		xdp_program__detach(dummy_prog, opt->iface_out.ifindex, opt->mode, 0);
	xdp_program__detach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
end_destroy:
	xdp_redirect_basic__destroy(skel);
end:
	sample_teardown();
	return ret;
}
