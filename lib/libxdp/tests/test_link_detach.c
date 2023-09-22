 /* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/err.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <linux/if_link.h>
#include "test_utils.h"

#include <xdp/libxdp.h>
#include <bpf/libbpf.h>

#define SKIPPED_TEST 249 // needs to match SKIPPED_TEST value in test_runner.sh

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <ifname>\n", progname);
	exit(EXIT_FAILURE);
}

static int check_link_detach(int ifindex, enum xdp_attach_mode mode) {
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	struct bpf_object *obj_prog = NULL;
	struct bpf_program *prog;
	struct xdp_multiprog *mp = NULL;
	int ret, prog_fd, link_fd =0;

	if (!ifindex)
		return -EINVAL;

	obj_prog = bpf_object__open("xdp_pass.o");
	if (!obj_prog) {
		ret = -errno;
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj_prog, "xdp_pass");
	if (!prog) {
		ret = -errno;
		goto out;
	}

	ret = bpf_object__load(obj_prog);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "Couldn't load object: %s\n", strerror(-ret));
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		ret = -errno;
		fprintf(stderr, "Couldn't get prog fd: %s\n", strerror(-ret));
		goto out;
	}
	if (mode == XDP_MODE_SKB)
		opts.flags = XDP_FLAGS_SKB_MODE;

	link_fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &opts);
	if (link_fd < 0) {
		ret = SKIPPED_TEST;
		fprintf(stderr, "Couldn't attach XDP prog to ifindex %d: %s\n", ifindex, strerror(errno));
		goto out;
	}

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	ret = libxdp_get_error(mp);
	if (ret) {
		fprintf(stderr, "Couldn't get multiprog on ifindex %d: %s\n",
			ifindex, strerror(-ret));
		goto out;
	}

	ret = xdp_multiprog__detach(mp);
out:
	if (link_fd > 0)
		close(link_fd);
	xdp_multiprog__close(mp);
	bpf_object__close(obj_prog);
	return ret;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int ifindex, ret;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	char *envval;

	envval = secure_getenv("VERBOSE_TESTS");

	silence_libbpf_logging();
	if (envval && envval[0] == '1')
		verbose_libxdp_logging();
	else
		silence_libxdp_logging();

	if (argc != 2)
		usage(argv[0]);

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Interface '%s' not found.\n", argv[1]);
		usage(argv[0]);
	}

	ret = check_link_detach(ifindex, XDP_MODE_SKB);
	if (ret) {
		fprintf(stderr, "Failed to detach XDP prog from ifindex %d mode %s: %s\n", 
			ifindex, "XDP_MODE_SKB", strerror(-ret));
		return ret;
	}
	ret = check_link_detach(ifindex, XDP_MODE_NATIVE);
	if (ret) {
		fprintf(stderr, "Failed to detach XDP prog from ifindex %d mode %s: %s\n",
			ifindex, "XDP_MODE_NATIVE", strerror(-ret));
	}
	return ret;
}
