/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __UTIL_H
#define __UTIL_H

#include "libbpf.h"

int check_bpf_environ(unsigned long min_rlimit);

int load_xdp_program(struct bpf_program *prog, int ifindex,
		     bool force, bool skb_mode);

#endif
