/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Check that a program supplied as a raw instruction stream can be created
 * with xdp_program__create() and attached as a dispatcher component, i.e.
 * that libxdp synthesises the BTF the kernel requires for BPF_PROG_TYPE_EXT.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/err.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xdp/libxdp.h>
#include <bpf/libbpf.h>

#include "../bpf_instr.h"
#include "test_utils.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

#define SKIPPED_TEST 249 // needs to match SKIPPED_TEST value in test_runner.sh

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <ifname>\n", progname);
	exit(EXIT_FAILURE);
}

/* The simplest possible component program: return XDP_PASS. */
static struct bpf_insn prog_insns[] = {
	BPF_MOV64_IMM(BPF_REG_0, XDP_PASS),
	BPF_EXIT_INSN(),
};

static int check_synth_insns(int ifindex)
{
	struct xdp_program *progs[2] = {};
	struct xdp_multiprog *mp = NULL;
	struct xdp_program *p;
	size_t num_progs = 0;
	int ret;

	DECLARE_LIBXDP_OPTS(xdp_program_opts, synth_opts,
			    .prog_name = "synth_pass",
			    .insns = prog_insns,
			    .insns_cnt = ARRAY_SIZE(prog_insns));

	progs[0] = xdp_program__create(&synth_opts);
	if (!progs[0]) {
		ret = -errno;
		fprintf(stderr, "Couldn't create program from insns: %s\n",
			strerror(-ret));
		goto out;
	}

	if (strcmp(xdp_program__name(progs[0]), "synth_pass")) {
		fprintf(stderr, "Unexpected program name '%s'\n",
			xdp_program__name(progs[0]));
		ret = -EINVAL;
		goto out;
	}

	/* A second program, so that a dispatcher is actually used rather than
	 * libxdp falling back to a single legacy attach.
	 */
	progs[1] = xdp_program__open_file("xdp_pass.o", NULL, NULL);
	if (libxdp_get_error(progs[1])) {
		ret = libxdp_get_error(progs[1]);
		progs[1] = NULL;
		fprintf(stderr, "Couldn't open xdp_pass.o: %s\n", strerror(-ret));
		goto out;
	}

	xdp_program__set_run_prio(progs[0], 10);
	xdp_program__set_run_prio(progs[1], 20);

	ret = xdp_program__attach_multi(progs, 2, ifindex, XDP_MODE_SKB, 0);
	if (ret) {
		fprintf(stderr, "Couldn't attach programs: %s\n", strerror(-ret));
		goto out;
	}

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (libxdp_get_error(mp)) {
		ret = libxdp_get_error(mp);
		mp = NULL;
		fprintf(stderr, "Couldn't get multiprog: %s\n", strerror(-ret));
		goto out_detach;
	}

	if (xdp_multiprog__is_legacy(mp)) {
		fprintf(stderr, "Got a legacy prog, expected a dispatcher\n");
		ret = -EINVAL;
		goto out_detach;
	}

	for (p = xdp_multiprog__next_prog(NULL, mp); p;
	     p = xdp_multiprog__next_prog(p, mp))
		num_progs++;

	if (num_progs != 2) {
		fprintf(stderr, "Expected 2 component progs, got %zu\n",
			num_progs);
		ret = -EINVAL;
		goto out_detach;
	}

	printf("Synthesised program attached as dispatcher component OK\n");
	ret = 0;

out_detach:
	xdp_program__detach_multi(progs, 2, ifindex, XDP_MODE_SKB, 0);
out:
	if (mp)
		xdp_multiprog__close(mp);
	if (progs[0])
		xdp_program__close(progs[0]);
	if (progs[1])
		xdp_program__close(progs[1]);
	return ret;
}

int main(int argc, char **argv)
{
	int ifindex, ret;

	if (argc != 2)
		usage(argv[0]);

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Interface '%s' not found\n", argv[1]);
		return EXIT_FAILURE;
	}

	silence_libbpf_logging();

	ret = check_synth_insns(ifindex);
	if (ret == -EOPNOTSUPP)
		return SKIPPED_TEST;

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
