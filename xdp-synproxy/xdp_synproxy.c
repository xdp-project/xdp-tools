// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <stdnoreturn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <sys/resource.h>

#include "logging.h"
#include "xdp_synproxy.skel.h"


#define STRERR_BUFSIZE 1024

static unsigned int ifindex;
static __u32 attached_prog_id;

static noreturn void cleanup()
{
        char errmsg[STRERR_BUFSIZE];
        struct xdp_program *p = NULL;
        int err;

	if (attached_prog_id == 0)
		exit(0);

	p = xdp_program__from_id(attached_prog_id);

	err = xdp_program__detach(p, ifindex, 0, 0);
	xdp_program__close(p);
        if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't detach BPF program: %s(%d)\n", errmsg, err);
		p = NULL;
		exit(1);
        }

	exit(0);
}

static noreturn void help(const char *progname)
{
	fprintf(stderr, "Usage: %s [--iface <iface>|--prog <prog_id>] [--mss4 <mss ipv4> --mss6 <mss ipv6> --wscale <wscale> --ttl <ttl>] [--ports <port1>,<port2>,...]\n",
		progname);
	exit(1);
}

static unsigned long parse_arg_ul(const char *progname, const char *arg, unsigned long limit)
{
	unsigned long res;
	char *endptr;

	errno = 0;
	res = strtoul(arg, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || arg[0] == '\0' || res > limit)
		help(progname);

	return res;
}

static void parse_options(int argc, char *argv[], unsigned int *ifindex, __u32 *prog_id,
			  __u64 *tcpipopts, char **ports)
{
	static struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "iface", required_argument, NULL, 'i' },
		{ "prog", required_argument, NULL, 'x' },
		{ "mss4", required_argument, NULL, 4 },
		{ "mss6", required_argument, NULL, 6 },
		{ "wscale", required_argument, NULL, 'w' },
		{ "ttl", required_argument, NULL, 't' },
		{ "ports", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 },
	};
	unsigned long mss4, wscale, ttl;
	unsigned long long mss6;
	unsigned int tcpipopts_mask = 0;

	if (argc < 2)
		help(argv[0]);

	*ifindex = 0;
	*prog_id = 0;
	*tcpipopts = 0;
	*ports = NULL;

	while (true) {
		int opt;

		opt = getopt_long(argc, argv, "", long_options, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			help(argv[0]);
			break;
		case 'i':
			*ifindex = if_nametoindex(optarg);
			if (*ifindex == 0)
				help(argv[0]);
			break;
		case 'x':
			*prog_id = parse_arg_ul(argv[0], optarg, UINT32_MAX);
			if (*prog_id == 0)
				help(argv[0]);
			break;
		case 4:
			mss4 = parse_arg_ul(argv[0], optarg, UINT16_MAX);
			tcpipopts_mask |= 1 << 0;
			break;
		case 6:
			mss6 = parse_arg_ul(argv[0], optarg, UINT16_MAX);
			tcpipopts_mask |= 1 << 1;
			break;
		case 'w':
			wscale = parse_arg_ul(argv[0], optarg, 14);
			tcpipopts_mask |= 1 << 2;
			break;
		case 't':
			ttl = parse_arg_ul(argv[0], optarg, UINT8_MAX);
			tcpipopts_mask |= 1 << 3;
			break;
		case 'p':
			*ports = optarg;
			break;
		default:
			help(argv[0]);
		}
	}
	if (optind < argc)
		help(argv[0]);

	if (tcpipopts_mask == 0xf) {
		if (mss4 == 0 || mss6 == 0 || wscale == 0 || ttl == 0)
			help(argv[0]);
		*tcpipopts = (mss6 << 32) | (ttl << 24) | (wscale << 16) | mss4;
	} else if (tcpipopts_mask != 0) {
		help(argv[0]);
	}

	if (*ifindex != 0 && *prog_id != 0)
		help(argv[0]);
	if (*ifindex == 0 && *prog_id == 0)
		help(argv[0]);
}

static int syncookie_attach(unsigned int ifindex)
{
	char errmsg[STRERR_BUFSIZE];
	struct xdp_program *p = NULL;
	struct xdp_synproxy *skel;
	int err;

	char *xdp_program_name = "syncookie_xdp";
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	skel = xdp_synproxy__open();
        if (!skel) {
		err = -errno;
		pr_warn("Couldn't open XDP program: %s\n", strerror(-err));
		return err;
	}

	xdp_opts.obj = skel->obj;
	xdp_opts.prog_name = xdp_program_name;
	p = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(p);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't create xdp program: %s(%d)\n", errmsg, err);
		goto out;
	}

	err = xdp_program__attach(p, ifindex, 0, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't attach BPF program: %s(%d)\n", errmsg, err);
		goto out;
	}
	attached_prog_id = xdp_program__id(p);

	err = 0;

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

out:
	xdp_program__close(p);
	xdp_synproxy__destroy(skel);
	return err;
}

static int syncookie_open_bpf_maps(__u32 prog_id, int *values_map_fd, int *ports_map_fd)
{
	struct bpf_prog_info prog_info;
	__u32 map_ids[8];
	__u32 info_len;
	int prog_fd;
	int err;
	int i;

	*values_map_fd = -1;
	*ports_map_fd = -1;

	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: bpf_prog_get_fd_by_id: %s\n", strerror(-prog_fd));
		return prog_fd;
	}

	prog_info = (struct bpf_prog_info) {
		.nr_map_ids = 8,
		.map_ids = (__u64)(unsigned long)map_ids,
	};
	info_len = sizeof(prog_info);

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err != 0) {
		fprintf(stderr, "Error: bpf_prog_get_info_by_fd: %s\n",
			strerror(-err));
		goto out;
	}

	if (prog_info.nr_map_ids < 2) {
		fprintf(stderr, "Error: Found %u BPF maps, expected at least 2\n",
			prog_info.nr_map_ids);
		err = -ENOENT;
		goto out;
	}

	for (i = 0; i < (int)prog_info.nr_map_ids; i++) {
		struct bpf_map_info map_info = {};
		int map_fd;

		err = bpf_map_get_fd_by_id(map_ids[i]);
		if (err < 0) {
			fprintf(stderr, "Error: bpf_map_get_fd_by_id: %s\n", strerror(-err));
			goto err_close_map_fds;
		}
		map_fd = err;

		info_len = sizeof(map_info);
		err = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_get_info_by_fd: %s\n",
				strerror(-err));
			close(map_fd);
			goto err_close_map_fds;
		}
		if (strcmp(map_info.name, "values") == 0) {
			*values_map_fd = map_fd;
			continue;
		}
		if (strcmp(map_info.name, "allowed_ports") == 0) {
			*ports_map_fd = map_fd;
			continue;
		}
		close(map_fd);
	}

	if (*values_map_fd != -1 && *ports_map_fd != -1) {
		err = 0;
		goto out;
	}

	err = -ENOENT;

err_close_map_fds:
	if (*values_map_fd != -1)
		close(*values_map_fd);
	if (*ports_map_fd != -1)
		close(*ports_map_fd);
	*values_map_fd = -1;
	*ports_map_fd = -1;

out:
	close(prog_fd);
	return err;
}

int main(int argc, char *argv[])
{
	int values_map_fd, ports_map_fd;
	__u64 tcpipopts;
	bool firstiter;
	__u64 prevcnt;
	__u32 prog_id;
	char *ports;
	int err = 0;

	parse_options(argc, argv, &ifindex, &prog_id, &tcpipopts, &ports);

	if (prog_id == 0) {
		err = syncookie_attach(ifindex);
		if (err < 0)
			goto out;
		prog_id = attached_prog_id;
	}

	err = syncookie_open_bpf_maps(prog_id, &values_map_fd, &ports_map_fd);
	if (err < 0)
		goto out;

	if (ports) {
		__u16 port_last = 0;
		__u32 port_idx = 0;
		char *p = ports;

		fprintf(stderr, "Replacing allowed ports\n");

		while (p && *p != '\0') {
			char *token = strsep(&p, ",");
			__u16 port;

			port = parse_arg_ul(argv[0], token, UINT16_MAX);
			err = bpf_map_update_elem(ports_map_fd, &port_idx, &port, BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Error: bpf_map_update_elem: %s\n", strerror(-err));
				fprintf(stderr, "Failed to add port %u (index %u)\n",
					port, port_idx);
				goto out_close_maps;
			}
			fprintf(stderr, "Added port %u\n", port);
			port_idx++;
		}
		err = bpf_map_update_elem(ports_map_fd, &port_idx, &port_last, BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_update_elem: %s\n", strerror(-err));
			fprintf(stderr, "Failed to add the terminator value 0 (index %u)\n",
				port_idx);
			goto out_close_maps;
		}
	}

	if (tcpipopts) {
		__u32 key = 0;

		fprintf(stderr, "Replacing TCP/IP options\n");

		err = bpf_map_update_elem(values_map_fd, &key, &tcpipopts, BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_update_elem: %s\n", strerror(-err));
			goto out_close_maps;
		}
	}

	if ((ports || tcpipopts) && attached_prog_id == 0)
		goto out_close_maps;

	prevcnt = 0;
	firstiter = true;
	while (true) {
		__u32 key = 1;
		__u64 value;

		err = bpf_map_lookup_elem(values_map_fd, &key, &value);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_lookup_elem: %s\n", strerror(-err));
			goto out_close_maps;
		}
		if (firstiter) {
			prevcnt = value;
			firstiter = false;
		}
		printf("SYNACKs generated: %llu (total %llu)\n", value - prevcnt, value);
		prevcnt = value;
		sleep(1);
	}

out_close_maps:
	close(values_map_fd);
	close(ports_map_fd);
out:
	return err == 0 ? 0 : 1;
}
