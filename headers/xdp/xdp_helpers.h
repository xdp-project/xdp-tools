/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */

#ifndef __XDP_HELPERS_H
#define __XDP_HELPERS_H

#define XDP_RUN_CONFIG_SECTION_ORIG "xdp_run_config"
#define XDP_RUN_CONFIG_SECTION_NEW ".data.xdp_run_config"

#if defined(USE_LIBBPF_V1_SECTION_NAMES)
#define XDP_RUN_CONFIG_SECTION XDP_RUN_CONFIG_SECTION_NEW
#else
#define XDP_RUN_CONFIG_SECTION XDP_RUN_CONFIG_SECTION_ORIG
#endif

#define _CONCAT(x,y) x ## y
#define XDP_RUN_CONFIG(f) _CONCAT(_,f) SEC(XDP_RUN_CONFIG_SECTION)

#define XDP_DEFAULT_RUN_PRIO 50
#define XDP_DEFAULT_CHAIN_CALL_ACTIONS (1<<XDP_PASS)

#endif
