// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#ifndef __LIBXDP_LIBXDP_H
#define __LIBXDP_LIBXDP_H

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "xdp_helpers.h"

#define XDP_BPFFS_ENVVAR "LIBXDP_BPFFS"

enum xdp_attach_mode {
                      XDP_MODE_UNSPEC = 0,
                      XDP_MODE_NATIVE,
                      XDP_MODE_SKB,
                      XDP_MODE_HW
};

struct xdp_program;
struct xdp_multiprog;

long libxdp_get_error(const void *ptr);
int libxdp_strerror(int err, char *buf, size_t size);


struct xdp_program *xdp_program__from_bpf_obj(struct bpf_object *obj,
					      const char *prog_name);
struct xdp_program *xdp_program__find_file(const char *filename,
					   const char *prog_name,
					   struct bpf_object_open_opts *opts);
struct xdp_program *xdp_program__open_file(const char *filename,
					   const char *prog_name,
					   struct bpf_object_open_opts *opts);
struct xdp_program *xdp_program__from_fd(int fd);
struct xdp_program *xdp_program__from_id(__u32 prog_id);

void xdp_program__close(struct xdp_program *xdp_prog);

const char *xdp_program__name(struct xdp_program *xdp_prog);
const unsigned char *xdp_program__tag(struct xdp_program *xdp_prog);
uint32_t xdp_program__id(struct xdp_program *xdp_prog);
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
void xdp_multiprog__close(struct xdp_multiprog *mp);
int xdp_multiprog__pin(struct xdp_multiprog *mp);
int xdp_multiprog__unpin(struct xdp_multiprog *mp);
int xdp_multiprog__attach(struct xdp_multiprog *mp,
                          int ifindex, bool force,
                          enum xdp_attach_mode mode);
struct xdp_multiprog *xdp_multiprog__get_from_ifindex(int ifindex);
struct xdp_program *xdp_multiprog__next_prog(struct xdp_program *prog,
					     struct xdp_multiprog *mp);

#endif
