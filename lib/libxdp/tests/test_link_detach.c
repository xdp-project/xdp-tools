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

#include "test_utils.h"

#include <xdp/libxdp.h>
#include <bpf/libbpf.h>

#define SKIPPED_TEST 249 // needs to match SKIPPED_TEST value in test_runner.sh

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <ifname>\n", progname);
	exit(EXIT_FAILURE);
}

static int check_link_detach(int ifindex) {
	struct bpf_object *obj_prog = NULL;
	struct bpf_program *prog;
	struct xdp_multiprog *mp = NULL;
	struct bpf_link *link = NULL;
	int ret;

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

	link = bpf_program__attach_xdp(prog, ifindex);
	if (!link) {
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
	bpf_link__destroy(link);
	xdp_multiprog__close(mp);
	bpf_object__close(obj_prog);
	return ret;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int ifindex;

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

	return check_link_detach(ifindex);
}
