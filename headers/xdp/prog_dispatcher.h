/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

#ifndef __PROG_DISPATCHER_H
#define __PROG_DISPATCHER_H

#include <linux/types.h>

#define XDP_METADATA_SECTION "xdp_metadata"
#define XDP_DISPATCHER_VERSION 1
/* default retval for dispatcher corresponds to the highest bit in the
 * chain_call_actions bitmap; we use this to make sure the dispatcher always
 * continues the calls chain if a function does not have an freplace program
 * attached.
 */
#define XDP_DISPATCHER_RETVAL 31

#ifndef MAX_DISPATCHER_ACTIONS
#define MAX_DISPATCHER_ACTIONS 10
#endif

struct xdp_dispatcher_config {
	__u8 num_progs_enabled;
	__u32 chain_call_actions[MAX_DISPATCHER_ACTIONS];
	__u32 run_prios[MAX_DISPATCHER_ACTIONS];
};

#endif
