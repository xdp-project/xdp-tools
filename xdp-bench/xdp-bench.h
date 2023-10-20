// SPDX-License-Identifier: GPL-2.0-only
#ifndef XDP_REDIRECT_H
#define XDP_REDIRECT_H

#include <xdp/libxdp.h>
#include "params.h"
#include "util.h"

#define MAX_IFACE_NUM 32

int do_drop(const void *cfg, const char *pin_root_path);
int do_pass(const void *cfg, const char *pin_root_path);
int do_tx(const void *cfg, const char *pin_root_path);
int do_redirect_basic(const void *cfg, const char *pin_root_path);
int do_redirect_cpumap(const void *cfg, const char *pin_root_path);
int do_redirect_devmap(const void *cfg, const char *pin_root_path);
int do_redirect_devmap_multi(const void *cfg, const char *pin_root_path);

enum basic_program_mode {
	BASIC_NO_TOUCH,
	BASIC_READ_DATA,
	BASIC_PARSE_IPHDR,
	BASIC_SWAP_MACS,
};

enum basic_load_mode {
	BASIC_LOAD_DPA,
	BASIC_LOAD_BYTES,
};

struct basic_opts {
	bool extended;
	bool rxq_stats;
	__u32 interval;
	enum xdp_attach_mode mode;
	enum basic_program_mode program_mode;
	enum basic_load_mode load_mode;
	struct iface iface_in;
};

struct redirect_opts {
	bool stats;
	bool extended;
	__u32 interval;
	enum xdp_attach_mode mode;
	struct iface iface_in;
	struct iface iface_out;
};

struct devmap_opts {
	bool stats;
	bool extended;
	bool load_egress;
	__u32 interval;
	enum xdp_attach_mode mode;
	struct iface iface_in;
	struct iface iface_out;
};

struct devmap_multi_opts {
	bool stats;
	bool extended;
	bool load_egress;
	__u32 interval;
	enum xdp_attach_mode mode;
	struct iface *ifaces;
};

enum cpumap_remote_action {
	ACTION_DISABLED,
	ACTION_DROP,
	ACTION_PASS,
	ACTION_REDIRECT,
};

enum cpumap_program_mode {
	CPUMAP_NO_TOUCH,
	CPUMAP_TOUCH_DATA,
	CPUMAP_CPU_ROUND_ROBIN,
	CPUMAP_CPU_L4_PROTO,
	CPUMAP_CPU_L4_PROTO_FILTER,
	CPUMAP_CPU_L4_HASH,
	CPUMAP_CPU_L4_SPORT,
	CPUMAP_CPU_L4_DPORT,
};

struct cpumap_opts {
	bool stats;
	bool extended;
	bool stress_mode;
	__u32 interval;
	__u32 qsize;
	struct u32_multi cpus;
	enum xdp_attach_mode mode;
	enum cpumap_remote_action remote_action;
	enum cpumap_program_mode program_mode;
	struct iface iface_in;
	struct iface redir_iface;
};

extern const struct basic_opts defaults_drop;
extern const struct basic_opts defaults_pass;
extern const struct basic_opts defaults_tx;
extern const struct redirect_opts defaults_redirect_basic;
extern const struct cpumap_opts defaults_redirect_cpumap;
extern const struct devmap_opts defaults_redirect_devmap;
extern const struct devmap_multi_opts defaults_redirect_devmap_multi;

#endif
