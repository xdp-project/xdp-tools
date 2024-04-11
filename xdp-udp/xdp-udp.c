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


#define STRERR_BUFSIZE 1024

static unsigned int ifindex;
static __u32 attached_prog_id;

static noreturn void help(const char *progname)
{
	fprintf(stderr, "Usage: %s [--iface <iface>|--prog <prog_id>] [--ports <port1>,<port2>,...]\n",
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

static void parse_options(int argc, char *argv[], unsigned int *ifindex, __u32 *prog_id, char **ports)
{
	static struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "iface", required_argument, NULL, 'i' },
		{ "prog", required_argument, NULL, 'x' },
		{ "ports", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 },
	};

	if (argc < 2)
		help(argv[0]);

	*ifindex = 0;
	*prog_id = 0;
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
		case 'p':
			*ports = optarg;
			break;
		default:
			help(argv[0]);
		}
	}
	if (optind < argc)
		help(argv[0]);

	if (*ifindex == 0 && *prog_id == 0)
		help(argv[0]);
}

static int open_bpf_maps(__u32 prog_id, int *ports_map_fd)
{
	struct bpf_prog_info prog_info;
	__u32 map_ids[8];
	__u32 info_len;
	int prog_fd;
	int err;
	int i;

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

	if (prog_info.nr_map_ids < 1) {
		fprintf(stderr, "Error: Found %u BPF maps, expected at least 1\n",
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
		if (strcmp(map_info.name, "udp_ports") == 0) {
			*ports_map_fd = map_fd;
			continue;
		}
		close(map_fd);
	}

	if (*ports_map_fd != -1) {
		err = 0;
		goto out;
	}

	err = -ENOENT;

err_close_map_fds:
	if (*ports_map_fd != -1)
		close(*ports_map_fd);
	*ports_map_fd = -1;

out:
	close(prog_fd);
	return err;
}

int main(int argc, char *argv[])
{
	int ports_map_fd;
	__u32 prog_id;
	char *ports;
	int err = 0;

	parse_options(argc, argv, &ifindex, &prog_id, &ports);

	err = open_bpf_maps(prog_id, &ports_map_fd);
	if (err < 0)
		goto out;

	if (ports) {
		__u16 port_last = 0;
		__u32 port_idx = 0;
		char *p = ports;

		fprintf(stderr, "Replacing allowed udp ports\n");

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

	if (ports && (attached_prog_id == 0))
		goto out_close_maps;

out_close_maps:
	close(ports_map_fd);
out:
	return err == 0 ? 0 : 1;
}
