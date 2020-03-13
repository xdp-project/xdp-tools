// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "xdp_helpers.h"
#include "util.h"

#define XDP_BPFFS_ENVVAR "LIBXDP_BPFFS"

struct xdp_program;
struct xdp_multiprog;

struct xdp_program *xdp_program__from_bpf_obj(struct bpf_object *obj,
					      const char *prog_name);
struct xdp_program *xdp_program__open_file(const char *filename,
					   const char *prog_name,
					   struct bpf_object_open_opts *opts);
struct xdp_program *xdp_program__from_fd(int fd);
struct xdp_program *xdp_program__from_id(__u32 prog_id);

void xdp_program__free(struct xdp_program *xdp_prog);

const char *xdp_program__name(struct xdp_program *xdp_prog);
unsigned int xdp_program__run_prio(struct xdp_program *xdp_prog);
void xdp_program__set_run_prio(struct xdp_program *xdp_prog, unsigned int run_prio);
bool xdp_program__chain_call_enabled(struct xdp_program *xdp_prog,
				     enum xdp_action action);
void xdp_program__set_chain_call_enabled(struct xdp_program *prog, unsigned int action,
                                         bool enabled);

int xdp_program__print_chain_call_actions(struct xdp_program *prog,
					  char *buf,
					  size_t buf_len);

struct xdp_multiprog *xdp_multiprog__generate(struct xdp_program **progs,
                                              size_t num_progs);
void xdp_multiprog__free(struct xdp_multiprog *mp);
int xdp_multiprog__pin(struct xdp_multiprog *mp);
int xdp_multiprog__unpin(struct xdp_multiprog *mp);
int xdp_multiprog__attach(struct xdp_multiprog *mp,
                          int ifindex, bool force,
                          enum xdp_attach_mode mode);
