/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __XDP_DISPATCHER_V1_H
#define __XDP_DISPATCHER_V1_H

#ifndef MAX_DISPATCHER_ACTIONS
#define MAX_DISPATCHER_ACTIONS 10
#endif

struct xdp_dispatcher_config_v1 {
	__u8 num_progs_enabled;
	__u32 chain_call_actions[MAX_DISPATCHER_ACTIONS];
	__u32 run_prios[MAX_DISPATCHER_ACTIONS];
};

#endif
