/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>
#include <arpa/inet.h>

#include "params.h"
#include "logging.h"

#define BUFSIZE 30

static int handle_bool(const struct option_wrapper *opt,
		       void *cfg, char *optarg)
{
	bool *opt_set;
	opt_set = (cfg + opt->cfg_offset);
	*opt_set = true;
	return 0;
}

static int handle_string(const struct option_wrapper *opt,
			 void *cfg, char *optarg)
{
	char **opt_set;
	opt_set = (cfg + opt->cfg_offset);
	*opt_set = optarg;
	return 0;
}

static int handle_u32(const struct option_wrapper *opt,
		      void *cfg, char *optarg)
{
	unsigned long val;
	__u32 *opt_set;

	opt_set = (cfg + opt->cfg_offset);

	val = strtoul(optarg, NULL, 10);
	if (errno || val > 0xffffffff)
		return -1;
	*opt_set = val;
	return 0;
}

static int handle_u16(const struct option_wrapper *opt,
		      void *cfg, char *optarg)
{
	unsigned long val;
	__u16 *opt_set;

	opt_set = (cfg + opt->cfg_offset);

	val = strtoul(optarg, NULL, 10);
	if (errno || val > 0xffff)
		return -1;
	*opt_set = val;
	return 0;
}

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

static int handle_macaddr(const struct option_wrapper *opt,
			  void *cfg, char *optarg)
{
	unsigned char **opt_set;

	opt_set = (cfg + opt->cfg_offset);
	return parse_mac(optarg, *opt_set);
}

static const struct flag_val *find_flag(const struct flag_val *flag_vals,
					const char *chr)
{
	while(flag_vals->flagstring) {
		if (strcmp(chr, flag_vals->flagstring) == 0)
			return flag_vals;
		flag_vals++;
	}
	return NULL;
}

static int handle_flags(const struct option_wrapper *opt,
			void *cfg, char *optarg)
{
	const struct flag_val *flag;
	int flagval = 0;
	char *c = NULL;
	int *opt_set;

	opt_set = (cfg + opt->cfg_offset);

	while (*optarg) {
		c = strchr(optarg, ',');
		if (c)
			*c = '\0';
		flag = find_flag(opt->typearg, optarg);
		if (!flag) {
			fprintf(stderr, "invalid flag: %s\n", optarg);
			return -1;
		}
		flagval |= flag->flagval;

		if (!c)
			break;
		optarg = c+1;
	}
	*opt_set = flagval;
	return 0;
}

static int handle_verbose(const struct option_wrapper *opt,
			  void *cfg, char *optarg)
{
	set_log_level(LOG_DEBUG);
	return 0;
}

static int handle_ifname(const struct option_wrapper *opt,
			  void *cfg, char *optarg)
{
	struct iface *iface;
	int ifindex;

	iface = (cfg + opt->cfg_offset);
	ifindex = if_nametoindex(optarg);
	if (!ifindex) {
		pr_warn("Couldn't find network interface '%s'.\n", optarg);
		return -1;
	}

	iface->ifname = optarg;
	iface->ifindex = ifindex;
	return 0;
}

void print_addr(char *buf, size_t buf_len, const struct ip_addr *addr)
{
	inet_ntop(addr->af, &addr->addr, buf, buf_len);
}

static int handle_ipaddr(const struct option_wrapper *opt,
			  void *cfg, char *optarg)
{
	struct ip_addr *addr;
	int err;
	int af;

	addr = (cfg + opt->cfg_offset);
	af = strchr(optarg, ':') ? AF_INET6 : AF_INET;

	if (inet_pton(af, optarg, &addr->addr) != 1) {
		pr_warn("Invalid IP address: %s\n", optarg);
		return -EINVAL;
	}

	addr->af = af;
	return 0;
}

static const struct opthandler {
	int (*func)(const struct option_wrapper *opt, void *cfg, char *optarg);
} handlers[__OPT_MAX] = {
			 {NULL},
			 {handle_flags},
			 {handle_bool},
			 {handle_string},
			 {handle_u16},
			 {handle_u32},
			 {handle_macaddr},
			 {handle_verbose},
			 {handle_ifname},
			 {handle_ipaddr}
};

void print_flags(char *buf, size_t buf_len, const struct flag_val *flags,
		 unsigned long flags_set)
{
	const struct flag_val *flag;
	bool first = true;

	for (flag = flags; buf_len && flag->flagstring; flag++) {
		int len;

		if (!(flag->flagval & flags_set))
			continue;

		if (!first) {
			*buf++ = ',';
			buf_len--;
		}
		first = false;
		len = snprintf(buf, buf_len, "%s", flag->flagstring);
		buf += len;
		buf_len -= len;
	}
}

static void print_help_flags(const struct option_wrapper *opt)
{
	char buf[100];

	print_flags(buf, sizeof(buf), opt->typearg, -1);

	printf("  %s (valid values: %s)", opt->help, buf);
}

static const struct helprinter {
	void (*func)(const struct option_wrapper *opt);
} help_printers[__OPT_MAX] = {
	{NULL},
	{print_help_flags}
};


static void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		enum option_type type;

		if (long_options[i].required != required)
			continue;

		type = long_options[i].type;

		if (long_options[i].option.val > 64) /* ord('A') = 65 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);

		if (help_printers[type].func != NULL)
			help_printers[type].func(&long_options[i]);
		else
			printf("  %s", long_options[i].help);
		printf("\n");
	}
}

bool is_prefix(const char *pfx, const char *str)
{
	if (!pfx)
		return false;
	if (strlen(str) < strlen(pfx))
		return false;

	return !memcmp(str, pfx, strlen(pfx));
}

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full)
{
	printf("\nUsage: %s [options]\n", prog_name);

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	printf("\n %s\n\n", doc);
	printf("Required options:\n");
	_print_options(long_options, true);
	printf("\n");
	printf("Other options:\n");
	_print_options(long_options, false);
	printf("\n");
}

static int option_wrappers_to_options(const struct option_wrapper *wrapper,
				      struct option **options,
				      char **optstring)
{
	struct option *new_options;
	char buf[100], *c = buf;
	int i, num;

	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;

	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
		*(c++) = wrapper[i].option.val;
		if (wrapper[i].option.has_arg)
			*(c++) = ':';
	}
	*(c++) = '\0';

	*optstring = strdup(buf);
	if (!*optstring)
		return -1;

	*options = new_options;
	return 0;
}

static struct option_wrapper *find_opt(struct option_wrapper *all_opts,
				       int optchar)
{
	while (all_opts->option.name != 0) {
		if (all_opts->option.val == optchar)
			return all_opts;
		all_opts++;
	}
	return NULL;
}

static int set_opt(void *cfg, struct option_wrapper *all_opts,
		   int optchar, char *optarg)
{
	struct option_wrapper *opt;
	int ret;

	opt = find_opt(all_opts, optchar);
	if (!opt)
		return -1;

	ret = handlers[opt->type].func(opt, cfg, optarg);
	if (!ret)
		opt->was_set = true;
	return ret;
}

void parse_cmdline_args(int argc, char **argv,
			struct option_wrapper *options_wrapper,
                        void *cfg, const char *prog, const char *doc)
{
	struct option_wrapper *opt_iter;
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	int opt, err = 0;
	char *optstring;

	if (option_wrappers_to_options(options_wrapper, &long_options, &optstring)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAILURE);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, &longindex)) != -1) {
		if (opt == 'h') {
			usage(prog, doc, options_wrapper, true);
			err = EXIT_FAILURE;
			goto out;
		}
		if (set_opt(cfg, options_wrapper, opt, optarg)) {
			usage(prog, doc, options_wrapper, full_help);
			err = EXIT_FAILURE;
			goto out;
		}
	}

	for (opt_iter = options_wrapper; opt_iter->option.name != 0; opt_iter++) {
		if (opt_iter->required && !opt_iter->was_set) {
			fprintf(stderr, "Missing required option '--%s'\n",
				opt_iter->option.name);
			usage(prog, doc, options_wrapper, full_help);
			err = EXIT_FAILURE;
			goto out;
		}
	}
out:
	free(long_options);
	free(optstring);
	if (err)
		exit(err);
}
