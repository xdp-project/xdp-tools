// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#ifndef __LIBXDP_LIBXDP_H
#define __LIBXDP_LIBXDP_H

#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XDP_BPFFS_ENVVAR "LIBXDP_BPFFS"
#define XDP_OBJECT_ENVVAR "LIBXDP_OBJECT_PATH"

enum xdp_attach_mode {
                      XDP_MODE_UNSPEC = 0,
                      XDP_MODE_NATIVE,
                      XDP_MODE_SKB,
                      XDP_MODE_HW
};

/* This is compatible with libbpf logging levels */
enum libxdp_print_level {
        LIBXDP_WARN,
        LIBXDP_INFO,
        LIBXDP_DEBUG,
};
typedef int (*libxdp_print_fn_t)(enum libxdp_print_level level,
				 const char *, va_list ap);

libxdp_print_fn_t libxdp_set_print(libxdp_print_fn_t fn);


struct xdp_program;
struct xdp_multiprog;

long libxdp_get_error(const void *ptr);
int libxdp_strerror(int err, char *buf, size_t size);
int libxdp_clean_references(int ifindex);


struct xdp_program *xdp_program__from_bpf_obj(struct bpf_object *obj,
					      const char *section_name);
struct xdp_program *xdp_program__find_file(const char *filename,
					   const char *section_name,
					   struct bpf_object_open_opts *opts);
struct xdp_program *xdp_program__open_file(const char *filename,
					   const char *section_name,
					   struct bpf_object_open_opts *opts);
struct xdp_program *xdp_program__from_fd(int fd);
struct xdp_program *xdp_program__from_id(__u32 prog_id);
struct xdp_program *xdp_program__from_pin(const char *pin_path);

void xdp_program__close(struct xdp_program *xdp_prog);

enum xdp_attach_mode xdp_program__is_attached(const struct xdp_program *xdp_prog,
                                              int ifindex);
const char *xdp_program__name(const struct xdp_program *xdp_prog);
const unsigned char *xdp_program__tag(const struct xdp_program *xdp_prog);
struct bpf_object *xdp_program__bpf_obj(struct xdp_program *xdp_prog);
const struct btf *xdp_program__btf(struct xdp_program *xdp_prog);
uint32_t xdp_program__id(const struct xdp_program *xdp_prog);
int xdp_program__fd(const struct xdp_program *xdp_prog);
unsigned int xdp_program__run_prio(const struct xdp_program *xdp_prog);
int xdp_program__set_run_prio(struct xdp_program *xdp_prog,
                              unsigned int run_prio);
bool xdp_program__chain_call_enabled(const struct xdp_program *xdp_prog,
				     enum xdp_action action);
int xdp_program__set_chain_call_enabled(struct xdp_program *prog,
                                        unsigned int action,
                                        bool enabled);
int xdp_program__print_chain_call_actions(const struct xdp_program *prog,
					  char *buf,
					  size_t buf_len);
int xdp_program__pin(struct xdp_program *xdp_prog, const char *pin_path);
int xdp_program__attach(struct xdp_program *xdp_prog,
                        int ifindex, enum xdp_attach_mode mode,
                        unsigned int flags);
int xdp_program__attach_multi(struct xdp_program **progs, size_t num_progs,
                              int ifindex, enum xdp_attach_mode mode,
                              unsigned int flags);
int xdp_program__detach(struct xdp_program *xdp_prog,
                        int ifindex, enum xdp_attach_mode mode,
                        unsigned int flags);
int xdp_program__detach_multi(struct xdp_program **progs, size_t num_progs,
                              int ifindex, enum xdp_attach_mode mode,
                              unsigned int flags);

struct xdp_multiprog *xdp_multiprog__get_from_ifindex(int ifindex);
struct xdp_program *xdp_multiprog__next_prog(const struct xdp_program *prog,
					     const struct xdp_multiprog *mp);
void xdp_multiprog__close(struct xdp_multiprog *mp);
int xdp_multiprog__detach(struct xdp_multiprog *mp);
enum xdp_attach_mode xdp_multiprog__attach_mode(const struct xdp_multiprog *mp);
struct xdp_program *xdp_multiprog__main_prog(const struct xdp_multiprog *mp);
struct xdp_program *xdp_multiprog__hw_prog(const struct xdp_multiprog *mp);
bool xdp_multiprog__is_legacy(const struct xdp_multiprog *mp);
int xdp_multiprog__program_count(const struct xdp_multiprog *mp);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
