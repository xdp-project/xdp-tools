/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __UTIL_H
#define __UTIL_H

#include "libbpf.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define STRERR_BUFSIZE 1024
#define BPF_DIR_MNT	"/sys/fs/bpf"
#define _textify(x)	#x
#define textify(x)	_textify(x)

#define FOR_EACH_MAP_KEY(_err, _map_fd, _map_key, _next_key)            \
  for(_err = bpf_map_get_next_key(_map_fd, NULL, &_next_key);           \
      !_err;                                                            \
      _err = bpf_map_get_next_key(_map_fd, &_map_key, &_next_key),      \
        _map_key = _next_key)

int check_bpf_environ(void);
int check_rlimit(unsigned long min_rlimit);

int load_xdp_program(struct bpf_program *prog, int ifindex,
		     bool force, bool skb_mode);

int get_xdp_prog_info(int ifindex, struct bpf_prog_info *info);
int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir);
int get_pinned_map_fd(const char *bpf_root, const char *map_name,
                      struct bpf_map_info *info);
int unlink_pinned_map(int dir_fd, const char *map_name);

const char *action2str(__u32 action);

int check_map_fd_info(const struct bpf_map_info *info,
                      const struct bpf_map_info *exp);

int prog_lock_get(const char *progname);
void prog_lock_release(int signal);

#endif
