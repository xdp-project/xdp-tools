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

int check_bpf_environ(unsigned long min_rlimit);

int load_xdp_program(struct bpf_program *prog, int ifindex,
		     bool force, bool skb_mode);

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir);
int get_pinned_map_fd(const char *bpf_root, const char *map_name);

#endif
