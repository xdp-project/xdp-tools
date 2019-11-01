/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PARAMS_H
#define __PARAMS_H

#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

enum option_type {
                  OPT_HELP,
                  OPT_FLAGS,
                  OPT_BOOL,
                  OPT_STRING,
                  OPT_U32,
                  OPT_MACADDR,
                  OPT_VERBOSE,
                  OPT_IFNAME,
                  __OPT_MAX
};

struct option_wrapper {
        struct option option;
        char *help;
        char *metavar;
        bool required;
        enum option_type type;
        void *typearg;
        size_t cfg_offset;
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

#define DEFINE_OPTION(_short, _long, _arg, _req, _type, _typearg,       \
                      _help, _metavar, _cfgtype, _cfgmember)            \
        {.option = {_long, _arg, NULL, _short},                         \
         .help = _help,                                                 \
         .metavar = _metavar,                                           \
         .required = _req,                                              \
         .type = _type,                                                 \
         .typearg = _typearg,                                           \
         .cfg_offset = offsetof(_cfgtype, _cfgmember)}

#define END_OPTIONS 	{}

void print_flags(char *buf, size_t buf_len, const struct flag_val *flags,
                 unsigned long flags_val);
bool is_prefix(const char *prefix, const char *string);
void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			struct option_wrapper *long_options,
                        void *cfg, const char *prog, const char *doc);

#endif /* __COMMON_PARAMS_H */
