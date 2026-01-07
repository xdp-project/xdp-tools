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

#define ARRAY_SIZE(_x) (sizeof(_x) / sizeof((_x)[0]))
#define EXIT_SKIPPED 249

static bool kern_compat;

static struct xdp_program *load_prog(void)
{
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts, .prog_name = "xdp_pass",
			    .find_filename = "xdp-dispatcher.o", );
	return xdp_program__create(&opts);
}

static int check_attached_progs(int ifindex, int count, bool devbound)
{
	struct xdp_multiprog *mp;
	int ret;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	ret = libxdp_get_error(mp);
	if (ret) {
		fprintf(stderr, "Couldn't get multiprog on ifindex %d: %s\n",
			ifindex, strerror(-ret));
		return ret;
	}

	ret = -EINVAL;

	if (xdp_multiprog__is_legacy(mp)) {
		fprintf(stderr, "Found legacy prog on ifindex %d\n", ifindex);
		goto out;
	}

	if (xdp_multiprog__program_count(mp) != count) {
		fprintf(stderr,
			"Expected %d programs loaded on ifindex %d, found %d\n",
			count, ifindex, xdp_multiprog__program_count(mp));
		goto out;
	}

	if (xdp_multiprog__xdp_dev_bound(mp) != devbound) {
		fprintf(stderr,
			"Multiprog on ifindex %d %s device binding, expected %s\n",
			ifindex,
			xdp_multiprog__xdp_dev_bound(mp) ? "supports" :
							   "does not support",
			devbound ? "support" : "no support");
		goto out;
	}

	ret = 0;

out:
	xdp_multiprog__close(mp);
	return ret;
}

static void print_test_result(const char *func, int ret)
{
	fflush(stderr);
	fprintf(stderr, "%s:\t%s\n", func,
		ret ? (ret == EXIT_SKIPPED ? "SKIPPED" : "FAILED") : "PASSED");
	fflush(stdout);
}

static int load_attach_prog(struct xdp_program **prog, int ifindex,
			    bool devbound)
{
	int ret;

	*prog = load_prog();
	if (!*prog) {
		ret = -errno;
		fprintf(stderr, "Couldn't load program: %s\n", strerror(-ret));
		return ret;
	}

	return xdp_program__attach(*prog, ifindex, XDP_MODE_NATIVE,
				   devbound ? XDP_ATTACH_DEVBIND : 0);
}

static int _check_load(int ifindex, bool devbound, bool should_succeed)
{
	struct xdp_program *prog = NULL;
	bool attached = false;
	int ret;

	if (!kern_compat && devbound) {
		ret = EXIT_SKIPPED;
		goto out;
	}

	ret = load_attach_prog(&prog, ifindex, devbound);
	attached = !ret;

	if (attached != should_succeed) {
		ret = -EINVAL;
		goto out;
	}

	if (should_succeed)
		ret = check_attached_progs(ifindex, 1, devbound);
	else
		ret = 0;

out:
	if (attached)
		xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
	xdp_program__close(prog);
	return ret;
}

static int check_load_devbound(int ifindex)
{
	int ret = _check_load(ifindex, true, true);
	print_test_result(__func__, ret);
	return ret;
}

static int check_load_nodevbound_success(int ifindex)
{
	int ret = _check_load(ifindex, false, true);
	print_test_result(__func__, ret);
	return ret;
}

static int check_load_devbound_multi(int ifindex)
{
	struct xdp_program *prog1 = NULL, *prog2 = NULL;
	int ret;

	if (!kern_compat) {
		ret = EXIT_SKIPPED;
		goto out;
	}

	ret = load_attach_prog(&prog1, ifindex, true);
	if (ret)
		goto out;

	ret = load_attach_prog(&prog2, ifindex, true);
	if (ret)
		goto out_prog1;

	ret = check_attached_progs(ifindex, 2, true);

	xdp_program__detach(prog2, ifindex, XDP_MODE_NATIVE, 0);
out_prog1:
	xdp_program__detach(prog1, ifindex, XDP_MODE_NATIVE, 0);
out:
	xdp_program__close(prog2);
	xdp_program__close(prog1);
	print_test_result(__func__, ret);
	return ret;
}

static int _check_load_mix(int ifindex, bool devbound1, bool devbound2)
{
	struct xdp_program *prog1 = NULL, *prog2 = NULL;
	int ret;

	if (!kern_compat && (devbound1 || devbound2)) {
		ret = EXIT_SKIPPED;
		goto out;
	}

	ret = load_attach_prog(&prog1, ifindex, devbound1);
	if (ret)
		goto out;

	/* First program attached, dispatcher supports device binding */
	ret = check_attached_progs(ifindex, 1, devbound1);
	if (ret)
		goto out;

	ret = load_attach_prog(&prog2, ifindex, devbound2);
	if (!ret) {
		xdp_program__detach(prog2, ifindex, XDP_MODE_NATIVE, 0);
		ret = -EINVAL;
		goto out_prog1;
	}

	/* Still only a single program loaded, with device binding */
	ret = check_attached_progs(ifindex, 1, devbound1);

out_prog1:
	xdp_program__detach(prog1, ifindex, XDP_MODE_NATIVE, 0);

out:
	xdp_program__close(prog2);
	xdp_program__close(prog1);
	return ret;
}

static int check_load_mix_devbound_nodevbound(int ifindex)
{
	int ret = _check_load_mix(ifindex, true, false);
	print_test_result(__func__, ret);
	return ret;
}

static int check_load_mix_nodevbound_devbound(int ifindex)
{
	int ret = _check_load_mix(ifindex, false, true);
	print_test_result(__func__, ret);
	return ret;
}

static int check_load_devbound_multiple_ifindex(int ifindex1, int ifindex2)
{
	struct xdp_program *prog = NULL;
	int ret;

	if (!kern_compat) {
		ret = EXIT_SKIPPED;
		goto out;
	}

	prog = load_prog();

	ret = xdp_program__attach(prog, ifindex1, XDP_MODE_NATIVE,
				  XDP_ATTACH_DEVBIND);
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	/* Still only a single program loaded, with device binding */
	ret = check_attached_progs(ifindex1, 1, true);
	if (ret)
		goto out;

	ret = xdp_program__attach(prog, ifindex2, XDP_MODE_NATIVE,
				  XDP_ATTACH_DEVBIND);
	if (!ret) {
		xdp_program__detach(prog, ifindex2, XDP_MODE_NATIVE, 0);
		ret = -EINVAL;
		goto out;
	}

out:
	xdp_program__detach(prog, ifindex1, XDP_MODE_NATIVE, 0);
	xdp_program__close(prog);
	print_test_result(__func__, ret == EXIT_SKIPPED ? ret : !ret);
	return !ret;
}

static int check_load_mixed_multiple_ifindex(int ifindex1, int ifindex2)
{
	struct xdp_program *prog = NULL;
	int ret;

	if (!kern_compat) {
		ret = EXIT_SKIPPED;
		goto out;
	}

	prog = load_prog();

	ret = xdp_program__attach(prog, ifindex1, XDP_MODE_NATIVE,
				  XDP_ATTACH_DEVBIND);
	if (ret)
		goto out;

	/* Still only a single program loaded, with device binding */
	ret = check_attached_progs(ifindex1, 1, true);
	if (ret)
		goto out_prog1;

	ret = xdp_program__attach(prog, ifindex2, XDP_MODE_NATIVE, 0);
	if (!ret) {
		xdp_program__detach(prog, ifindex2, XDP_MODE_NATIVE, 0);
		ret = -EINVAL;
	}

out_prog1:
	xdp_program__detach(prog, ifindex1, XDP_MODE_NATIVE, 0);
out:
	xdp_program__close(prog);
	print_test_result(__func__, ret == EXIT_SKIPPED ? ret : !ret);
	return !ret;
}

static int check_load2_mixed_multiple_ifindex(int ifindex1, int ifindex2)
{
	struct xdp_program *prog1 = NULL, *prog2 = NULL;
	int ret;

	if (!kern_compat) {
		ret = EXIT_SKIPPED;
		goto out;
	}

	ret = load_attach_prog(&prog1, ifindex1, true);
	if (ret)
		goto out;

	/* First program attached, dispatcher supports device binding */
	ret = check_attached_progs(ifindex1, 1, true);
	if (ret)
		goto out_prog1;

	ret = load_attach_prog(&prog2, ifindex2, false);
	if (ret)
		goto out_prog1;

	/* Still only a single program loaded, with device binding */
	ret = check_attached_progs(ifindex2, 1, false);

out_prog1:
	xdp_program__detach(prog1, ifindex1, XDP_MODE_NATIVE, 0);

out:
	xdp_program__detach(prog2, ifindex2, XDP_MODE_NATIVE, 0);
	xdp_program__close(prog2);
	xdp_program__close(prog1);
	print_test_result(__func__, ret);

	return ret;
}

static bool check_devbound_compat(void)
{
#ifdef HAVE_LIBBPF_BPF_PROGRAM__FLAGS
	struct xdp_program *test_prog;
	struct bpf_program *prog;
	struct bpf_object *obj;
	bool ret = false;
	int err;

	test_prog = load_prog();
	if (!test_prog)
		return false;

	obj = xdp_program__bpf_obj(test_prog);
	if (!obj)
		goto out;

	prog = bpf_object__find_program_by_name(obj, "xdp_pass");
	if (!prog)
		goto out;

	bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY);
	err = bpf_object__load(obj);
	if (!err) {
		printf("Kernel supports XDP programs with device binding\n");
		ret = true;
	} else {
		printf("Kernel DOES NOT support XDP programs with device binding\n");
	}
	fflush(stdout);

out:
	xdp_program__close(test_prog);
	return ret;
#else
        return -EOPNOTSUPP;
#endif
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <ifname1> <ifname2>\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	int ifindex1, ifindex2, ret = 0;

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

	if (argc != 3)
		usage(argv[0]);

	ifindex1 = if_nametoindex(argv[1]);
	if (!ifindex1) {
		fprintf(stderr, "Interface '%s' not found.\n", argv[1]);
		usage(argv[0]);
	}

	ifindex2 = if_nametoindex(argv[2]);
	if (!ifindex2) {
		fprintf(stderr, "Interface '%s' not found.\n", argv[1]);
		usage(argv[0]);
	}

	kern_compat = check_devbound_compat();
	ret = check_load_devbound(ifindex1);
	ret |= check_load_nodevbound_success(ifindex1);
	ret |= check_load_devbound_multi(ifindex1);
	ret |= check_load_mix_devbound_nodevbound(ifindex1);
	ret |= check_load_mix_nodevbound_devbound(ifindex1);
	ret |= check_load_devbound_multiple_ifindex(ifindex1, ifindex2);
	ret |= check_load_mixed_multiple_ifindex(ifindex1, ifindex2);
	ret |= check_load2_mixed_multiple_ifindex(ifindex1, ifindex2);

	return ret == EXIT_SKIPPED ? 0 : ret;
}
