// SPDX-License-Identifier: GPL-2.0

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
#include <linux/bpf.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <xdp/libxdp.h>

#include "xdp_sample.h"
#include "xdp_redirect.h"
#include "xdp_redirect_devmap_multi.skel.h"

static int ifaces[MAX_IFACE_NUM] = {};

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_MAP_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT |
		  SAMPLE_DEVMAP_XMIT_CNT_MULTI | SAMPLE_SKIP_HEADING;

DEFINE_SAMPLE_INIT(xdp_redirect_devmap_multi);

static int update_mac_map(struct bpf_map *map)
{
	int mac_map_fd = bpf_map__fd(map);
	unsigned char mac_addr[6];
	unsigned int ifindex;
	int i, ret = -1;

	for (i = 0; ifaces[i] > 0; i++) {
		ifindex = ifaces[i];

		ret = get_mac_addr(ifindex, mac_addr);
		if (ret < 0) {
			fprintf(stderr, "get interface %d mac failed\n",
				ifindex);
			return ret;
		}

		ret = bpf_map_update_elem(mac_map_fd, &ifindex, mac_addr, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to update mac address for ifindex %d\n",
				ifindex);
			return ret;
		}
	}

	return 0;
}

const struct devmap_multi_opts defaults_redirect_devmap_multi = { .mode = XDP_MODE_NATIVE,
								  .interval = 2 };


int do_redirect_devmap_multi(const void *cfg, __unused const char *pin_root_path)
{
	const struct devmap_multi_opts *opt = cfg;

	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct bpf_program *ingress_prog = NULL;
	struct bpf_devmap_val devmap_val = {};
	struct xdp_redirect_devmap_multi *skel;
	struct xdp_program *xdp_prog = NULL;
	struct bpf_map *forward_map = NULL;
	bool first = true, tried = false;
	int ret = EXIT_FAIL_OPTION;
	struct iface *iface;
	int i;

	if (opt->extended)
		sample_switch_mode();

	if (opt->mode == XDP_MODE_SKB)
		/* devmap_xmit tracepoint not available */
		mask &= ~(SAMPLE_DEVMAP_XMIT_CNT |
			  SAMPLE_DEVMAP_XMIT_CNT_MULTI);

	if (opt->stats)
		mask |= SAMPLE_REDIRECT_CNT;

restart:
	skel = xdp_redirect_devmap_multi__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_redirect_devmap_multi__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	/* Set to NULL when not restarting */
	if (!ingress_prog)
		ingress_prog = skel->progs.redir_multi_native;
	/* Set to NULL when not restarting */
	if (!forward_map)
		forward_map = skel->maps.forward_map_native;

	ret = sample_init_pre_load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = EXIT_FAIL_OPTION;
	/* opt parsing enforces num <= MAX_IFACES_NUM */
	for (i = 0, iface = opt->ifaces; iface; i++, iface = iface->next) {
		skel->rodata->from_match[i] = iface->ifindex;
		skel->rodata->to_match[i] = iface->ifindex;
	}


	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(ingress_prog);
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		fprintf(stderr, "Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	for (iface = opt->ifaces; iface; iface = iface->next) {

		ret = xdp_program__attach(xdp_prog, iface->ifindex, opt->mode, 0);
		if (ret) {
			if (first) {
				if (opt->mode == XDP_MODE_SKB && !tried) {
					fprintf(stderr,
						"Trying fallback to sizeof(int) as value_size for devmap in generic mode\n");
					ingress_prog = skel->progs.redir_multi_general;
					forward_map = skel->maps.forward_map_general;
					tried = true;
					xdp_program__close(xdp_prog);
					xdp_redirect_devmap_multi__destroy(skel);
					sample_teardown();
					goto restart;
				}
				fprintf(stderr, "Failed to attach XDP program to iface %s: %s\n",
					iface->ifname, strerror(-ret));
				goto end_destroy;
			}
			fprintf(stderr, "Failed to attach XDP program to ifindex %d: %s\n",
				ifindex, strerror(-ret));
			goto end_detach;
		}

		/* Add all the interfaces to forward group and attach
		 * egress devmap program if exist
		 */
		devmap_val.ifindex = iface->ifindex;
		if (opt->load_egress)
			devmap_val.bpf_prog.fd = bpf_program__fd(skel->progs.xdp_devmap_prog);
		ret = bpf_map_update_elem(bpf_map__fd(forward_map), &iface->ifindex, &devmap_val, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to update devmap value: %s\n",
				strerror(errno));
			ret = EXIT_FAIL_BPF;
			goto end_detach;
		}

		first = false;
	}

	if (opt->load_egress) {
		/* Update mac_map with all egress interfaces' mac addr */
		if (update_mac_map(skel->maps.mac_map) < 0) {
			fprintf(stderr, "Updating mac address failed\n");
			ret = EXIT_FAIL;
			goto end_detach;
		}
	}

	ret = sample_init(skel, mask, 0, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}

	ret = sample_run(opt->interval, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}
	ret = EXIT_OK;
end_detach:
	for (iface = opt->ifaces; iface; iface = iface->next)
		xdp_program__detach(xdp_prog, iface->ifindex, opt->mode, 0);
end_destroy:
	xdp_program__close(xdp_prog);
	xdp_redirect_devmap_multi__destroy(skel);
end:
	sample_teardown();
	return ret;
}
