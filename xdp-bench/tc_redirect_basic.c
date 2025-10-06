// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Tariro Mukute
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
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/tc_act/tc_bpf.h>

#include "logging.h"
#include "xdp-bench.h"
#include "xdp_sample.h"
#include "tc_redirect_basic.skel.h"

// Define which statistics counters to use.
static int mask = SAMPLE_RX_CNT;

DEFINE_SAMPLE_INIT(tc_redirect_basic);

// const struct redirect_opts defaults_redirect_basic = { .interval = 2 };

// Helper function to attach/detach the clsact qdisc.
static int attach_clsact_qdisc(struct tc_redirect_basic *skel, int ifindex, bool attach)
{
    struct bpf_program *bpf_prog;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                        .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

    bpf_prog = bpf_object__find_program_by_name(skel->obj, "tc_redirect_prog");
    tc_opts.prog_fd = bpf_program__fd(bpf_prog);
    if (!tc_opts.prog_fd) {
        pr_warn("Failed to find program fd for tc_redirect_prog\n");
        return -ENOENT;
    }

    int err;

    if (!attach)
        return bpf_tc_hook_destroy(&hook);

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        pr_warn("Failed to create TC hook: %s\n", strerror(-err));
        return err;
    }

    err = bpf_tc_attach(&hook, &tc_opts);
    if (err) {
        pr_warn("Failed to attach TC program: %s\n", strerror(-err));
        bpf_tc_hook_destroy(&hook);
        return err;
    }
    return 0;
}

int do_tc_redirect_basic(const void *cfg, __unused const char *pin_root_path)
{
	const struct redirect_opts *opt = cfg;
	struct tc_redirect_basic *skel;
	char str[2 * IF_NAMESIZE + 1];
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts);
	int ret = EXIT_FAIL_OPTION;

    // Open the BPF skeleton.
	skel = tc_redirect_basic__open();
	if (!skel) {
		pr_warn("Failed to tc_redirect_basic__open: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

    // Initialise shared sample components before loading the BPF object.
	ret = sample_init_pre_load(skel, opt->iface_in.ifname);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

    // Set the output interface index in the BPF program's read-only data section.
	skel->rodata->ifindex_out = opt->iface_out.ifindex;

    // Load the BPF program into the kernel.
    ret = tc_redirect_basic__load(skel);
    if (ret) {
        pr_warn("Failed to load BPF skeleton: %s\n", strerror(-ret));
        goto end_destroy;
    }

    ret = attach_clsact_qdisc(skel, opt->iface_in.ifindex, true);
    if (ret)
        goto end_destroy;
    // ret = attach_clsact_qdisc(skel, opt->iface_out.ifindex, true);
    // if (ret)
    //     goto end_detach_qdisc_in;

    // Initialize the statistics collection.
	ret = sample_init(skel, mask, opt->iface_in.ifindex, opt->iface_out.ifindex);
	if (ret < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}

	ret = EXIT_FAIL;

	safe_strncpy(str, get_driver_name(opt->iface_in.ifindex), sizeof(str));
	pr_info("Redirecting from %s (ifindex %d; driver %s) to %s (ifindex %d; driver %s)\n",
		opt->iface_in.ifname, opt->iface_in.ifindex, str,
		opt->iface_out.ifname, opt->iface_out.ifindex, get_driver_name(opt->iface_out.ifindex));

    // Run the main statistics polling loop.
	ret = sample_run(opt->interval, NULL, NULL);
	if (ret < 0) {
		pr_warn("Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
	} else {
	    ret = EXIT_OK;
    }

end_detach:
    // Detach the TC program on exit.
    bpf_tc_detach(&(const struct bpf_tc_hook){
        .ifindex = opt->iface_in.ifindex,
        .attach_point = BPF_TC_INGRESS
    }, &tc_opts);
    // attach_clsact_qdisc(skel, opt->iface_out.ifindex, false);
// end_detach_qdisc_in:
    attach_clsact_qdisc(skel, opt->iface_in.ifindex, false);
end_destroy:
	tc_redirect_basic__destroy(skel);
end:
	sample_teardown();
	return ret;
}