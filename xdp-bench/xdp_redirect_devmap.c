// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
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
#include <xdp/libxdp.h>
#include <linux/if_link.h>

#include "logging.h"

#include "xdp-bench.h"
#include "xdp_sample.h"
#include "xdp_redirect_devmap.skel.h"

static int mask = SAMPLE_RX_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI;

DEFINE_SAMPLE_INIT(xdp_redirect_devmap);

const struct devmap_opts defaults_redirect_devmap = { .mode = XDP_MODE_NATIVE,
						      .interval = 2 };

int do_redirect_devmap(const void *cfg, __unused const char *pin_root_path)
{
	const struct devmap_opts *opt = cfg;

	struct xdp_program *xdp_prog = NULL, *dummy_prog = NULL;
	const char *prog_name = "redir_devmap_native";
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct bpf_devmap_val devmap_val = {};
	struct bpf_map *tx_port_map = NULL;
	struct xdp_redirect_devmap *skel;
	struct bpf_program *prog = NULL;
	char str[2 * IF_NAMESIZE + 1];
	int ret = EXIT_FAIL_OPTION;
	bool tried = false;
	int key = 0;

	if (opt->extended)
		sample_switch_mode();

	if (opt->mode == XDP_MODE_SKB)
		/* devmap_xmit tracepoint not available */
		mask &= ~(SAMPLE_DEVMAP_XMIT_CNT |
			  SAMPLE_DEVMAP_XMIT_CNT_MULTI);

	if (opt->stats)
		mask |= SAMPLE_REDIRECT_CNT;

restart:
	skel = xdp_redirect_devmap__open();
	if (!skel) {
		pr_warn("Failed to xdp_redirect_devmap__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	/* Make sure we only load the one XDP program we are interested in */
	while ((prog = bpf_object__next_program(skel->obj, prog)) != NULL)
		if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP &&
		    bpf_program__expected_attach_type(prog) == BPF_XDP)
			bpf_program__set_autoload(prog, false);

	if (tried) {
		tx_port_map = skel->maps.tx_port_general;
		bpf_program__set_autoload(skel->progs.xdp_redirect_devmap_egress, false);
#ifdef HAVE_LIBBPF_BPF_MAP__SET_AUTOCREATE
		bpf_map__set_autocreate(skel->maps.tx_port_native, false);
#else
		pr_warn("Libbpf is missing bpf_map__set_autocreate(), fallback won't work\n");
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
#endif
	} else {
#ifdef HAVE_LIBBPF_BPF_MAP__SET_AUTOCREATE
		bpf_map__set_autocreate(skel->maps.tx_port_general, false);
#endif
		tx_port_map = skel->maps.tx_port_native;
	}

	ret = sample_init_pre_load(skel, opt->iface_in.ifname);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	/* Load 2nd xdp prog on egress. */
	if (opt->load_egress) {
		ret = get_mac_addr(opt->iface_out.ifindex, skel->rodata->tx_mac_addr);
		if (ret < 0) {
			pr_warn("Failed to get interface %s mac address: %s\n",
				opt->iface_out.ifname, strerror(-ret));
			ret = EXIT_FAIL;
			goto end_destroy;
		}
	}

	skel->rodata->from_match[0] = opt->iface_in.ifindex;
	skel->rodata->to_match[0] = opt->iface_out.ifindex;

	opts.obj = skel->obj;
	opts.prog_name = prog_name;
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
		/* First try with struct bpf_devmap_val as value for generic
		 * mode, then fallback to sizeof(int) for older kernels.
		 */
		if (!opt->load_egress && !tried) {
			pr_warn("Attempting fallback to int-sized devmap\n");
			prog_name = "redir_devmap_general";
			tried = true;

			xdp_program__close(xdp_prog);
			xdp_redirect_devmap__destroy(skel);
			sample_teardown();
			xdp_prog = NULL;
			goto restart;
		}
		pr_warn("Failed to attach XDP program: %s\n",
			strerror(-ret));
		ret = EXIT_FAIL_XDP;
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

	xdp_program__set_xdp_frags_support(dummy_prog, true);

	ret = xdp_program__attach(dummy_prog, opt->iface_out.ifindex, opt->mode, 0);
	if (ret < 0) {
		pr_warn("Failed to attach dummy program: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_detach;
	}

	devmap_val.ifindex = opt->iface_out.ifindex;
	if (opt->load_egress)
		devmap_val.bpf_prog.fd = bpf_program__fd(skel->progs.xdp_redirect_devmap_egress);
	ret = bpf_map_update_elem(bpf_map__fd(tx_port_map), &key, &devmap_val, 0);
	if (ret < 0) {
		pr_warn("Failed to update devmap value: %s\n",
			strerror(errno));
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
		goto end_destroy;
	}
	ret = EXIT_OK;
end_detach:
	if (dummy_prog)
		xdp_program__detach(dummy_prog, opt->iface_out.ifindex, opt->mode, 0);
	xdp_program__detach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
end_destroy:
	xdp_program__close(xdp_prog);
	xdp_program__close(dummy_prog);
	xdp_redirect_devmap__destroy(skel);
end:
	sample_teardown();
	return ret;
}
