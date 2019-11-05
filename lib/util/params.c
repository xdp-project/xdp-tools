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

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	unsigned int v[ETH_ALEN];
	int len, i;

	/* Based on https://stackoverflow.com/a/20553913 */
	len = sscanf(str, "%x:%x:%x:%x:%x:%x%*c",
		     &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);

	if (len != ETH_ALEN)
		return -EINVAL;

	for (i = 0; i < ETH_ALEN; i++) {
		if (v[i] > 0xFF)
			return -EINVAL;
		mac[i] = v[i];
	}
	return 0;
}

static int handle_macaddr(const struct option_wrapper *opt,
			  void *cfg, char *optarg)
{
	struct mac_addr *opt_set;
	int err;

	opt_set = (cfg + opt->cfg_offset);
	err = parse_mac(optarg, opt_set->addr);
	if (err)
		pr_warn("Invalid MAC address: %s\n", optarg);

	return err;
}

void print_macaddr(char *buf, size_t buf_len, const struct mac_addr *addr)
{
	size_t len;
	int i;

	for (i = 0; buf_len > 0 && i < ETH_ALEN; i++) {
		len = snprintf(buf, buf_len, "%02x", addr->addr[i]);
		buf += len;
		buf_len -= len;

		if (i < ETH_ALEN-1) {
			*buf++ = ':';
			buf_len -= 1;
		}
	}
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


static void _print_positional(const struct option_wrapper *long_options)
{
	const struct option_wrapper *opt;

	FOR_EACH_OPTION(long_options, opt) {
		if (opt->option.has_arg != positional_argument)
			continue;

		printf(" %s", opt->metavar);
	}
}

static void _print_options(const struct option_wrapper *long_options,
			   bool required)
{
	const struct option_wrapper *opt;

	FOR_EACH_OPTION(long_options, opt) {
		if (opt->required != required)
			continue;

		if (opt->option.has_arg == positional_argument) {
			printf("  %-24s", opt->metavar);
		} else {
			char buf[BUFSIZE];
			int pos;

			if (opt->option.val > 64) /* ord('A') = 65 */
				printf(" -%c,", opt->option.val);
			else
				printf("    ");
			pos = snprintf(buf, BUFSIZE, " --%s",
				       opt->option.name);
			if (opt->metavar)
				snprintf(&buf[pos], BUFSIZE-pos, " %s",
					 opt->metavar);
			printf("%-22s", buf);
		}

		if (help_printers[opt->type].func != NULL)
			help_printers[opt->type].func(opt);
		else
			printf("  %s", opt->help);
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
	printf("\nUsage: %s [options]", prog_name);
	_print_positional(long_options);
	printf("\n");

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
	printf(" -v, --verbose              Enable verbose logging\n");
	printf(" -h, --help                 Show this help\n");
	printf("\n");
}

static int option_wrappers_to_options(const struct option_wrapper *wrapper,
				      struct option **options,
				      char **optstring)
{
	struct option *new_options, *nopt;
	const struct option_wrapper *opt;
	int num = 0, num_cmn = 0;
	char buf[100], *c = buf;

	struct option common_opts[] = {
	       {"help", no_argument, NULL, 'h'},
	       {"verbose", no_argument, NULL, 'v'},
	       {}
	};

	for (nopt = common_opts; nopt->name; nopt++) {
		num++; num_cmn++;
		*c++ = nopt->val;
	}

	FOR_EACH_OPTION(wrapper, opt)
		if(opt->option.has_arg != positional_argument)
			num++;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	memcpy(new_options, &common_opts, sizeof(struct option) * num_cmn);
	nopt = new_options + num_cmn;

	FOR_EACH_OPTION(wrapper, opt) {
		if (opt->option.has_arg == positional_argument)
			continue;
		memcpy(nopt++, &opt->option, sizeof(struct option));
		if (opt->option.val) {
			*(c++) = opt->option.val;
			if (opt->option.has_arg)
				*(c++) = ':';
		}
	}
	*(c++) = '\0';

	*optstring = strdup(buf);
	if (!*optstring) {
		free(new_options);
		return -1;
	}

	*options = new_options;
	return 0;
}

static struct option_wrapper *find_opt(struct option_wrapper *all_opts,
				       int optchar)
{
	struct option_wrapper *opt;

	FOR_EACH_OPTION(all_opts, opt)
		if (opt->option.val == optchar)
			return opt;
	return NULL;
}

static int set_opt(void *cfg, struct option_wrapper *all_opts,
		   int optchar, char *optarg)
{
	struct option_wrapper *opt;
	int ret;

	if (!cfg)
		return -EFAULT;

	opt = find_opt(all_opts, optchar);
	if (!opt)
		return -1;

	ret = handlers[opt->type].func(opt, cfg, optarg);
	if (!ret)
		opt->was_set = true;
	return ret;
}

static int set_pos_opt(void *cfg, struct option_wrapper *all_opts, char *optarg)
{
	struct option_wrapper *opt, *set_opt = NULL;
	int ret;

	FOR_EACH_OPTION(all_opts, opt) {
		if (opt->option.has_arg == positional_argument && !opt->was_set) {
			set_opt = opt;
			break;
		}
	}

	if (!set_opt)
		return -ENOENT;

	ret = handlers[opt->type].func(set_opt, cfg, optarg);
	if (!ret)
		set_opt->was_set = true;
	return ret;
}

int parse_cmdline_args(int argc, char **argv,
		       struct option_wrapper *options_wrapper,
		       void *cfg, const char *prog, const char *doc)
{
	struct option_wrapper *opt_iter;
	struct option *long_options;
	bool full_help = false;
	int i, opt, err = 0;
	int longindex = 0;
	char *optstring;

	if (option_wrappers_to_options(options_wrapper, &long_options, &optstring)) {
		pr_warn("Unable to malloc()\n");
		return -ENOMEM;
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'h':
			usage(prog, doc, options_wrapper, true);
			err = EXIT_FAILURE;
			goto out;
		case 'v':
			set_log_level(LOG_DEBUG);
			break;
		default:
			if (set_opt(cfg, options_wrapper, opt, optarg)) {
				usage(prog, doc, options_wrapper, full_help);
				err = EXIT_FAILURE;
				goto out;
			}
			break;
		}
	}

	for (i = optind; i < argc; i++) {
		if (set_pos_opt(cfg, options_wrapper, argv[i])) {
			usage(prog, doc, options_wrapper, full_help);
			err = EXIT_FAILURE;
			goto out;
		}
	}

	FOR_EACH_OPTION(options_wrapper, opt_iter) {
		if (opt_iter->required && !opt_iter->was_set) {
			if (opt_iter->option.has_arg == positional_argument)
				pr_warn("Missing required parameter %s\n",
					opt_iter->metavar);
			else
				pr_warn("Missing required option '--%s'\n",
					opt_iter->option.name);
			usage(prog, doc, options_wrapper, full_help);
			err = EXIT_FAILURE;
			goto out;
		}
	}
out:
	free(long_options);
	free(optstring);

	return err;
}
