// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "xdp_helpers.h"

struct xdp_program {
	/* one of prog or prog_fd should be set */
	struct bpf_program *prog;
	int prog_fd;
	unsigned int run_prio;
	unsigned int chain_call_actions; // bitmap
};

struct xdp_program *xdp_get_program(const struct bpf_object *obj,
				    const char *name);
struct xdp_program *xdp_get_program_by_id(__u32 id);
