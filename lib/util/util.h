/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __UTIL_H
#define __UTIL_H

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "params.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define STRERR_BUFSIZE 1024
#define _textify(x) #x
#define textify(x) _textify(x)

#define __unused __attribute__((unused))

#ifndef BPF_DIR_MNT
#define BPF_DIR_MNT "/sys/fs/bpf"
#endif

#ifndef BPF_OBJECT_PATH
#define BPF_OBJECT_PATH "/usr/lib/bpf"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define FOR_EACH_MAP_KEY(_err, _map_fd, _map_key, _prev_key)                \
	for (_err = bpf_map_get_next_key(_map_fd, NULL, &_map_key);         \
             !_err;                                                         \
	     _prev_key = _map_key,                                          \
	    _err = bpf_map_get_next_key(_map_fd, &_prev_key, &_map_key))

#define min(x, y) ((x) < (y) ? x : y)
#define max(x, y) ((x) > (y) ? x : y)

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})
#endif

#ifndef roundup
#define roundup(x, y)                            \
	({                                       \
		typeof(y) __y = y;               \
		(((x) + (__y - 1)) / __y) * __y; \
	})
#endif

int try_snprintf(char *buf, size_t buf_len, const char *format, ...);
int make_dir_subdir(const char *parent, const char *dir);

int check_bpf_environ(const char *pin_root_path);
int double_rlimit();

int attach_xdp_program(struct xdp_program *prog, const struct iface *iface,
		       enum xdp_attach_mode mode, const char *pin_root_dir);
int detach_xdp_program(struct xdp_program *prog, const struct iface *iface,
		       enum xdp_attach_mode mode, const char *pin_root_dir);

int find_bpf_file(char *buf, size_t buf_size, const char *progname);
struct bpf_object *open_bpf_file(const char *progname,
				 struct bpf_object_open_opts *opts);

typedef int (*program_callback)(const struct iface *iface,
				struct xdp_program *prog,
				enum xdp_attach_mode mode, void *arg);
typedef int (*multiprog_callback)(const struct iface *iface,
				  const struct xdp_multiprog *mp, void *arg);
int get_pinned_program(const struct iface *iface, const char *pin_root_path,
		       enum xdp_attach_mode *mode, struct xdp_program **prog);
int iterate_pinned_programs(const char *pin_root_path, program_callback cb,
			    void *arg);
int iterate_iface_multiprogs(multiprog_callback cb, void *arg);

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir);
int get_pinned_map_fd(const char *bpf_root, const char *map_name,
		      struct bpf_map_info *info);
int unlink_pinned_map(int dir_fd, const char *map_name);

const char *action2str(__u32 action);

int prog_lock_get(const char *progname);
void prog_lock_release(int signal);

const char *get_libbpf_version(void);
int iface_print_status(const struct iface *iface);

#endif
