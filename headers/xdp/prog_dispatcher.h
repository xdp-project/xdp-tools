/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

#ifndef __PROG_DISPATCHER_H
#define __PROG_DISPATCHER_H

#include <linux/types.h>

#define XDP_METADATA_SECTION "xdp_metadata"
#define XDP_DISPATCHER_VERSION 1

#ifndef MAX_DISPATCHER_ACTIONS
#define MAX_DISPATCHER_ACTIONS 10
#endif

struct xdp_dispatcher_config {
	__u8 num_progs_enabled;
	__u32 chain_call_actions[MAX_DISPATCHER_ACTIONS];
};

#endif
