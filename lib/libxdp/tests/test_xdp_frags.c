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

# define ARRAY_SIZE(_x) (sizeof(_x) / sizeof((_x)[0]))

static bool kern_compat;


static struct xdp_program *load_prog(void)
{
        DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
                            .prog_name = "xdp_pass",
                            .find_filename = "xdp-dispatcher.o",
                );
        return xdp_program__create(&opts);
}

static int check_attached_progs(int ifindex, int count, bool frags)
{
        struct xdp_multiprog *mp;
        int ret;

        /* If the kernel does not support frags, we always expect
         * frags support to be disabled on a returned dispatcher
         */
        if (!kern_compat)
                frags = false;

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
		fprintf(stderr, "Expected %d programs loaded on ifindex %d, found %d\n",
                        count, ifindex, xdp_multiprog__program_count(mp));
		goto out;
	}

	if (xdp_multiprog__xdp_frags_support(mp) != frags) {
		fprintf(stderr,
			"Multiprog on ifindex %d %s frags, expected %s\n",
			ifindex,
			xdp_multiprog__xdp_frags_support(mp) ?
				"supports" :
				"does not support",
			frags ? "support" : "no support");
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
	fprintf(stderr, "%s:\t%s\n", func, ret ? "FAILED" : "PASSED");
        fflush(stdout);
}

static int load_attach_prog(struct xdp_program **prog, int ifindex, bool frags)
{
        int ret;

        *prog = load_prog();
	if (!*prog) {
		ret = -errno;
		fprintf(stderr, "Couldn't load program: %s\n", strerror(-ret));
		return ret;
	}

        ret = xdp_program__set_xdp_frags_support(*prog, frags);
        if (ret)
                return ret;

        return xdp_program__attach(*prog, ifindex, XDP_MODE_NATIVE, 0);
}

static int _check_load(int ifindex, bool frags, bool should_succeed)
{
        struct xdp_program *prog = NULL;
        bool attached;
        int ret;

        ret = load_attach_prog(&prog, ifindex, frags);
        attached = !ret;

	if (attached != should_succeed) {
		ret = -EINVAL;
		goto out;
	}

        if (should_succeed)
                ret = check_attached_progs(ifindex, 1, frags);
        else
                ret = 0;

out:
        if (attached)
                xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
        xdp_program__close(prog);
        return ret;
}

static int check_load_frags(int ifindex_bigmtu, int ifindex_smallmtu)
{
        int ret = _check_load(ifindex_smallmtu, true, true);
        if (!ret && ifindex_bigmtu)
                _check_load(ifindex_bigmtu, true, true);
        print_test_result(__func__, ret);
        return ret;
}

static int check_load_nofrags_success(int ifindex)
{
        int ret = _check_load(ifindex, false, true);
        print_test_result(__func__, ret);
        return ret;
}

static int check_load_nofrags_fail(int ifindex)
{
        int ret = _check_load(ifindex, false, false);
        print_test_result(__func__, ret);
        return ret;
}
static int check_load_frags_multi(int ifindex)
{
        struct xdp_program *prog1 = NULL, *prog2 = NULL;
        int ret;

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

static int check_load_mix_small(int ifindex)
{
        struct xdp_program *prog1 = NULL, *prog2 = NULL;
        int ret;

        ret = load_attach_prog(&prog1, ifindex, true);
        if (ret)
                goto out;

        /* First program attached, dispatcher supports frags */
	ret = check_attached_progs(ifindex, 1, true);
        if (ret)
                goto out;

        ret = load_attach_prog(&prog2, ifindex, false);
	if (ret)
		goto out_prog1;

        /* Mixed program attachment, dispatcher should not support frags */
	ret = check_attached_progs(ifindex, 2, false);

        ret = xdp_program__detach(prog2, ifindex, XDP_MODE_NATIVE, 0) || ret;
        if (ret)
                goto out_prog1;

        /* Second program removed, back to frags-only */
	ret = check_attached_progs(ifindex, 1, true) || ret;

out_prog1:
        xdp_program__detach(prog1, ifindex, XDP_MODE_NATIVE, 0);

out:
        xdp_program__close(prog2);
        xdp_program__close(prog1);
        print_test_result(__func__, ret);
        return ret;
}

static int check_load_mix_big(int ifindex)
{
        struct xdp_program *prog1 = NULL, *prog2 = NULL;
        int ret;

        ret = load_attach_prog(&prog1, ifindex, true);
        if (ret)
                goto out;

        /* First program attached, dispatcher supports frags */
	ret = check_attached_progs(ifindex, 1, true);
        if (ret)
                goto out;

        /* Second non-frags program should fail on big-MTU device */
        ret = load_attach_prog(&prog2, ifindex, false);
	if (!ret) {
		xdp_program__detach(prog2, ifindex, XDP_MODE_NATIVE, 0);
		ret = -EINVAL;
		goto out_prog1;
	}

	/* Still only a single program loaded, with frags support */
	ret = check_attached_progs(ifindex, 1, true);

out_prog1:
        xdp_program__detach(prog1, ifindex, XDP_MODE_NATIVE, 0);

out:
        xdp_program__close(prog2);
        xdp_program__close(prog1);
        print_test_result(__func__, ret);
        return ret;
}


static bool check_frags_compat(void)
{
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

	bpf_program__set_flags(prog, BPF_F_XDP_HAS_FRAGS);
        err = bpf_object__load(obj);
	if (!err) {
		printf("Kernel supports XDP programs with frags\n");
                ret = true;
	} else {
		printf("Kernel DOES NOT support XDP programs with frags\n");
	}
        fflush(stdout);

out:
	xdp_program__close(test_prog);
	return ret;
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <ifname_bigmtu> <ifname_smallmtu>\n", progname);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int ifindex_bigmtu, ifindex_smallmtu, ret;

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

	ifindex_bigmtu = if_nametoindex(argv[1]);
	ifindex_smallmtu = if_nametoindex(argv[2]);
	if (!ifindex_bigmtu || !ifindex_smallmtu) {
		fprintf(stderr, "Interface '%s' or '%s' not found.\n", argv[1], argv[2]);
                usage(argv[0]);
	}

        kern_compat = check_frags_compat();

        ret = check_load_frags(kern_compat ? ifindex_bigmtu : 0, ifindex_smallmtu);
        ret = check_load_nofrags_success(ifindex_smallmtu) || ret;
	if (kern_compat) {
		ret = check_load_nofrags_fail(ifindex_bigmtu) || ret;
		ret = check_load_frags_multi(ifindex_bigmtu) || ret;
                ret = check_load_mix_big(ifindex_bigmtu) || ret;
	}
	ret = check_load_mix_small(ifindex_smallmtu) || ret;

	return ret;
}
