/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PARAMS_H
#define __PARAMS_H

#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "libbpf.h"

enum option_type {
                  OPT_NONE,
                  OPT_BOOL,
                  OPT_FLAGS,
                  OPT_STRING,
                  OPT_U16,
                  OPT_U32,
                  OPT_MACADDR,
                  OPT_IFNAME,
                  OPT_IPADDR,
                  __OPT_MAX
};

struct prog_option {
	enum option_type type;
	size_t cfg_size;
	size_t cfg_offset;
	char *name;
	char short_opt;
	char *help;
	char *metavar;
	void *typearg;
	bool required;
	bool positional;
	bool was_set;
};

struct flag_val {
        char *flagstring;
        int flagval;
};

struct iface {
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

#define DEFINE_OPTION(_name, _type, _cfgtype, _cfgmember, ...)           \
	{.cfg_size = sizeof(_cfgtype),                                  \
	.name = _name,                                  \
	.type = _type,			      \
	.cfg_offset = offsetof(_cfgtype, _cfgmember),   \
	__VA_ARGS__}

#define END_OPTIONS 	{}

#define FOR_EACH_OPTION(_options, _opt)                 \
        for (_opt = _options; _opt->type != OPT_NONE; _opt++)

#define positional_argument (optional_argument +1)

void print_flags(char *buf, size_t buf_len, const struct flag_val *flags,
                 unsigned long flags_val);
void print_addr(char *buf, size_t buf_len, const struct ip_addr *addr);
void print_macaddr(char *buf, size_t buf_len, const struct mac_addr *addr);
bool is_prefix(const char *prefix, const char *string);
void usage(const char *prog_name, const char *doc,
           const struct prog_option *long_options, bool full);

int parse_cmdline_args(int argc, char **argv,
                       struct prog_option *long_options,
                       void *cfg, const char *prog, const char *doc);

#endif /* __COMMON_PARAMS_H */
