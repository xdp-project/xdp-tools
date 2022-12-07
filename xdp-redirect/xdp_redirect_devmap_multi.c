// SPDX-License-Identifier: GPL-2.0
static const char *__doc__ =
"XDP multi redirect tool, using BPF_MAP_TYPE_DEVMAP and BPF_F_BROADCAST flag for bpf_redirect_map\n"
"Usage: xdp-redirect devmap_multi <IFINDEX|IFNAME> <IFINDEX|IFNAME> ... <IFINDEX|IFNAME>\n";

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
#include "xdp_redirect_devmap_multi.skel.h"

#define MAX_IFACE_NUM 32
static int ifaces[MAX_IFACE_NUM] = {};

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_MAP_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT |
		  SAMPLE_DEVMAP_XMIT_CNT_MULTI | SAMPLE_SKIP_HEADING;

DEFINE_SAMPLE_INIT(xdp_redirect_devmap_multi);

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "skb-mode", no_argument, NULL, 'S' },
	{ "load-egress", no_argument, NULL, 'X' },
	{ "stats", no_argument, NULL, 's' },
	{ "interval", required_argument, NULL, 'i' },
	{ "verbose", no_argument, NULL, 'v' },
	{}
};

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

int xdp_redirect_devmap_multi_main(int argc, char **argv)
{
	enum xdp_attach_mode xdp_mode = XDP_MODE_NATIVE;
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct bpf_program *ingress_prog = NULL;
	struct bpf_devmap_val devmap_val = {};
	struct xdp_redirect_devmap_multi *skel;
	struct xdp_program *xdp_prog = NULL;
	struct bpf_map *forward_map = NULL;
	bool xdp_devmap_attached = false;
	int ret = EXIT_FAIL_OPTION;
	unsigned long interval = 2;
	char ifname[IF_NAMESIZE];
	unsigned int ifindex;
	bool tried = false;
	bool error = true;
	int i, opt;

	while ((opt = getopt_long(argc, argv, "hSXi:vs",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'S':
			xdp_mode = XDP_MODE_SKB;
			/* devmap_xmit tracepoint not available */
			mask &= ~(SAMPLE_DEVMAP_XMIT_CNT |
				  SAMPLE_DEVMAP_XMIT_CNT_MULTI);
			break;
		case 'X':
			xdp_devmap_attached = true;
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			sample_switch_mode();
			break;
		case 's':
			mask |= SAMPLE_REDIRECT_MAP_CNT;
			break;
		case 'h':
			error = false;
			__attribute__((__fallthrough__));
		default:
			sample_usage(argv, long_options, __doc__, mask, error);
			return ret;
		}
	}

	if (argc <= optind + 1) {
		sample_usage(argv, long_options, __doc__, mask, error);
		return ret;
	}

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
	for (i = 0; i < MAX_IFACE_NUM && argv[optind + i]; i++) {
		ifaces[i] = if_nametoindex(argv[optind + i]);
		if (!ifaces[i])
			ifaces[i] = strtoul(argv[optind + i], NULL, 0);
		if (!if_indextoname(ifaces[i], ifname)) {
			fprintf(stderr, "Bad interface index or name\n");
			sample_usage(argv, long_options, __doc__, mask, true);
			goto end_destroy;
		}

		skel->rodata->from_match[i] = ifaces[i];
		skel->rodata->to_match[i] = ifaces[i];
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

	for (i = 0; ifaces[i] > 0; i++) {
		ifindex = ifaces[i];

		ret = xdp_program__attach(xdp_prog, ifindex, xdp_mode, 0);
		if (ret) {
			if (i == 0) {
				if (xdp_mode == XDP_MODE_SKB && !tried) {
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
				fprintf(stderr, "Failed to attach XDP program to ifindex %d: %s\n",
					ifindex, strerror(-ret));
				goto end_destroy;
			}
			fprintf(stderr, "Failed to attach XDP program to ifindex %d: %s\n",
				ifindex, strerror(-ret));
			goto end_detach;
		}

		/* Add all the interfaces to forward group and attach
		 * egress devmap program if exist
		 */
		devmap_val.ifindex = ifindex;
		if (xdp_devmap_attached)
			devmap_val.bpf_prog.fd = bpf_program__fd(skel->progs.xdp_devmap_prog);
		ret = bpf_map_update_elem(bpf_map__fd(forward_map), &ifindex, &devmap_val, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to update devmap value: %s\n",
				strerror(errno));
			ret = EXIT_FAIL_BPF;
			goto end_detach;
		}
	}

	if (xdp_devmap_attached) {
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

	ret = sample_run(interval, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}
	ret = EXIT_OK;
end_detach:
	for (i = 0; ifaces[i] > 0; i++)
		xdp_program__detach(xdp_prog, ifaces[i], xdp_mode, 0);
end_destroy:
	xdp_program__close(xdp_prog);
	xdp_redirect_devmap_multi__destroy(skel);
end:
	sample_teardown();
	return ret;
}
