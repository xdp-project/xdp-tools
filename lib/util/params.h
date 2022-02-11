/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PARAMS_H
#define __PARAMS_H

#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>

enum option_type {
	OPT_NONE,
	OPT_BOOL,
	OPT_FLAGS,
	OPT_STRING,
	OPT_U16,
	OPT_U32,
	OPT_U32_MULTI,
	OPT_MACADDR,
	OPT_IFNAME,
	OPT_IFNAME_MULTI,
	OPT_IPADDR,
	OPT_ENUM,
	OPT_MULTISTRING,
	__OPT_MAX
};

struct prog_option {
	enum option_type type;
	size_t cfg_size;
	size_t cfg_offset;
	size_t opt_size;
	char *name;
	char short_opt;
	char *help;
	char *metavar;
	void *typearg;
	bool required;
	bool positional;
	unsigned int min_num;
	unsigned int max_num;
	unsigned int num_set;
};

struct flag_val {
	const char *flagstring;
	unsigned int flagval;
};

struct enum_val {
	const char *name;
	unsigned int value;
};

struct multistring {
	const char **strings;
	size_t num_strings;
};

struct u32_multi {
	__u32 *vals;
	size_t num_vals;
};

struct iface {
	struct iface *next;
	char *ifname;
	int ifindex;
};

struct ip_addr {
	int af;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
};

struct mac_addr {
	unsigned char addr[ETH_ALEN];
};

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

#define DEFINE_OPTION(_name, _type, _cfgtype, _cfgmember, ...)               \
	{                                                                    \
		.cfg_size = sizeof(_cfgtype),                                \
		.opt_size = sizeof_field(_cfgtype, _cfgmember),              \
		.cfg_offset = offsetof(_cfgtype, _cfgmember), .name = _name, \
		.type = _type, __VA_ARGS__                                   \
	}

#define END_OPTIONS \
	{           \
	}

#define FOR_EACH_OPTION(_options, _opt) \
	for (_opt = _options; _opt->type != OPT_NONE; _opt++)

struct prog_command {
	const char *name;
	int (*func)(const void *cfg, const char *pin_root_path);
	struct prog_option *options;
	const void *default_cfg;
	char *doc;
	bool no_cfg;
};

#define DEFINE_COMMAND_NAME(_name, _func, _doc)                               \
	{                                                                     \
		.name = _name, .func = do_##_func,                        \
		.options = _func##_options, .default_cfg = &defaults_##_func, \
		.doc = _doc                                                   \
	}
#define DEFINE_COMMAND(_name, _doc) DEFINE_COMMAND_NAME(textify(_name), _name, _doc)

#define DEFINE_COMMAND_NODEF(_name, _doc)                   \
	{                                                   \
		.name = textify(_name), .func = do_##_name, \
		.options = _name##_options, .doc = _doc     \
	}

#define END_COMMANDS \
	{            \
	}

const char *get_enum_name(const struct enum_val *vals, unsigned int value);
void print_flags(char *buf, size_t buf_len, const struct flag_val *flags,
		 unsigned long flags_val);
void print_addr(char *buf, size_t buf_len, const struct ip_addr *addr);
void print_macaddr(char *buf, size_t buf_len, const struct mac_addr *addr);
bool macaddr_is_null(const struct mac_addr *addr);
bool ipaddr_is_null(const struct ip_addr *addr);
bool is_prefix(const char *prefix, const char *string);
void usage(const char *prog_name, const char *doc,
	   const struct prog_option *long_options, bool full);

int parse_cmdline_args(int argc, char **argv, struct prog_option *long_options,
		       void *cfg, const char *prog, const char *usage_cmd,
		       const char *doc, const void *defaults);

int dispatch_commands(const char *argv0, int argc, char **argv,
		      const struct prog_command *cmds, size_t cfg_size,
		      const char *prog_name, bool needs_bpffs);

#endif /* __COMMON_PARAMS_H */
