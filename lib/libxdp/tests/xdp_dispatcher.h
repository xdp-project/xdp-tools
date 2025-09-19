/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __XDP_DISPATCHER_H
#define __XDP_DISPATCHER_H

#ifndef MAX_DISPATCHER_ACTIONS
#define MAX_DISPATCHER_ACTIONS 10
#endif

struct xdp_dispatcher_config_v1 {
	__u8 num_progs_enabled;
	__u32 chain_call_actions[MAX_DISPATCHER_ACTIONS];
	__u32 run_prios[MAX_DISPATCHER_ACTIONS];
};

#define XDP_DISPATCHER_VERSION_V1 1

struct xdp_dispatcher_config_v2 {
	__u8 magic;                         /* Set to XDP_DISPATCHER_MAGIC */
	__u8 dispatcher_version;            /* Set to XDP_DISPATCHER_VERSION */
	__u8 num_progs_enabled;             /* Number of active program slots */
	__u8 is_xdp_frags;                  /* Whether this dispatcher is loaded with XDP frags support */
	__u32 chain_call_actions[MAX_DISPATCHER_ACTIONS];
	__u32 run_prios[MAX_DISPATCHER_ACTIONS];
	__u32 program_flags[MAX_DISPATCHER_ACTIONS];
};

#define XDP_DISPATCHER_MAGIC 236
#define XDP_DISPATCHER_VERSION_V2 2

#endif
