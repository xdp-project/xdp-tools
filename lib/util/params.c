/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE

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
#include "util.h"

#define BUFSIZE 30

static bool opt_needs_arg(const struct prog_option *opt)
{
	return opt->type > OPT_BOOL && !opt->positional;
}

static bool opt_is_multi(const struct prog_option *opt)
{
	return opt->type == OPT_MULTISTRING;
}

static int handle_bool(char *optarg, void *tgt, void *typearg)
{
	bool *opt_set = tgt;

	*opt_set = true;
	return 0;
}

static int handle_string(char *optarg, void *tgt, void *typearg)
{
	char **opt_set = tgt;

	*opt_set = optarg;
	return 0;
}

static int handle_multistring(char *optarg, void *tgt, void *typearg)
{
	struct multistring *opt_set = tgt;
	void *ptr;

	ptr = reallocarray(opt_set->strings, sizeof(*opt_set->strings),
			   opt_set->num_strings + 1);
	if (!ptr)
		return -errno;

	opt_set->strings = ptr;
	opt_set->strings[opt_set->num_strings++] = optarg;
	return 0;
}

static int handle_u32(char *optarg, void *tgt, void *typearg)
{
	__u32 *opt_set = tgt;
	unsigned long val;

	val = strtoul(optarg, NULL, 10);
	if (errno || val > 0xffffffff)
		return -1;

	*opt_set = val;
	return 0;
}

static int handle_u16(char *optarg, void *tgt, void *typearg)
{
	__u16 *opt_set = tgt;
	unsigned long val;

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

static int handle_macaddr(char *optarg, void *tgt, void *typearg)
{
	struct mac_addr *opt_set = tgt;
	int err;

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

static int handle_flags(char *optarg, void *tgt, void *typearg)
{
	const struct flag_val *flag, *flag_vals = typearg;
	unsigned int *opt_set = tgt;
	unsigned int flagval = 0;
	char *c = NULL;

	while (*optarg) {
		c = strchr(optarg, ',');
		if (c)
			*c = '\0';
		flag = find_flag(flag_vals, optarg);
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

static int handle_ifname(char *optarg, void *tgt, void *typearg)
{
	struct iface *iface = tgt;
	int ifindex;

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

static int handle_ipaddr(char *optarg, void *tgt, void *typearg)
{
	struct ip_addr *addr = tgt;
 	int af;

	af = strchr(optarg, ':') ? AF_INET6 : AF_INET;

	if (inet_pton(af, optarg, &addr->addr) != 1) {
		pr_warn("Invalid IP address: %s\n", optarg);
		return -EINVAL;
	}

	addr->af = af;
	return 0;
}

static const struct enum_val *find_enum(const struct enum_val *enum_vals,
					const char *chr)
{
	while(enum_vals->name) {
		if (strcmp(chr, enum_vals->name) == 0)
			return enum_vals;
		enum_vals++;
	}
	return NULL;
}

static int handle_enum(char *optarg, void *tgt, void *typearg)
{
	const struct enum_val *val, *all_vals = typearg;
	unsigned int *opt_set = tgt;

	val = find_enum(all_vals, optarg);
	if (!val) {
		fprintf(stderr, "invalid value: %s\n", optarg);
		return -1;
	}
	*opt_set = val->value;
	return 0;
}

static void print_enum_vals(char *buf, size_t buf_len, const struct enum_val *vals)
{
	const struct enum_val *val;
	bool first = true;

	for (val = vals; buf_len && val->name; val++) {
		int len;

		if (!first) {
			*buf++ = ',';
			buf_len--;
		}
		first = false;

		len = snprintf(buf, buf_len, "%s", val->name);
		buf += len;
		buf_len -= len;
	}
}

const char *get_enum_name(const struct enum_val *vals, unsigned int value)
{
	const struct enum_val *val;

	for (val = vals; val->name; val++)
		if (val->value == value)
			return val->name;
	return NULL;
}

static const struct opthandler {
	int (*func)(char *optarg, void *tgt, void *typearg);
} handlers[__OPT_MAX] = {
			 {NULL},
			 {handle_bool},
			 {handle_flags},
			 {handle_string},
			 {handle_u16},
			 {handle_u32},
			 {handle_macaddr},
			 {handle_ifname},
			 {handle_ipaddr},
			 {handle_enum},
			 {handle_multistring}
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

static void print_help_flags(const struct prog_option *opt)
{
	char buf[100] = {};

	if (!opt->typearg)
		pr_warn("Missing typearg for opt %s\n", opt->name);
	else
		print_flags(buf, sizeof(buf), opt->typearg, -1);

	printf("  %s (valid values: %s)", opt->help, buf);
}

static void print_help_enum(const struct prog_option *opt)
{
	char buf[100] = {};

	if (!opt->typearg)
		pr_warn("Missing typearg for opt %s\n", opt->name);
	else
		print_enum_vals(buf, sizeof(buf), opt->typearg);

	printf("  %s (valid values: %s)", opt->help, buf);
}



static const struct helprinter {
	void (*func)(const struct prog_option *opt);
} help_printers[__OPT_MAX] = {
	{NULL},
	{NULL},
	{print_help_flags},
	{NULL},
	{NULL},
	{NULL},
	{NULL},
	{NULL},
	{NULL},
	{print_help_enum},
	{NULL}
};


static void _print_positional(const struct prog_option *long_options)
{
	const struct prog_option *opt;

	FOR_EACH_OPTION(long_options, opt) {
		if (!opt->positional)
			continue;

		printf(" %s", opt->metavar ?: opt->name);
	}
}

static void _print_options(const struct prog_option *poptions,
			   bool required)
{
	const struct prog_option *opt;

	FOR_EACH_OPTION(poptions, opt) {
		if (opt->required != required)
			continue;

		if (opt->positional) {
			printf("  %-24s", opt->metavar ?: opt->name);
		} else {
			char buf[BUFSIZE];
			int pos;

			if (opt->short_opt > 64) /* ord('A') = 65 */
				printf(" -%c,", opt->short_opt);
			else
				printf("    ");
			pos = snprintf(buf, BUFSIZE, " --%s", opt->name);
			if (opt->metavar)
				snprintf(&buf[pos], BUFSIZE-pos, " %s",
					 opt->metavar);
			printf("%-22s", buf);
		}

		if (help_printers[opt->type].func != NULL)
			help_printers[opt->type].func(opt);
		else if (opt->help)
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
           const struct prog_option *poptions, bool full)
{
	const struct prog_option *opt;
	int num_req = 0;

	printf("\nUsage: %s [options]", prog_name);
	_print_positional(poptions);
	printf("\n");

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	FOR_EACH_OPTION(poptions, opt)
		if (opt->required)
			num_req++;

	printf("\n %s\n\n", doc);
	if (num_req) {
		printf("Required parameters:\n");
		_print_options(poptions, true);
		printf("\n");
	}
	printf("Options:\n");
	_print_options(poptions, false);
	printf(" -v, --verbose              Enable verbose logging (-vv: more verbose)\n");
	printf(" -h, --help                 Show this help\n");
	printf("\n");
}

static int prog_options_to_options(const struct prog_option *poptions,
				   struct option **options,
				   char **optstring)
{
	struct option *new_options, *nopt;
	const struct prog_option *opt;
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

	FOR_EACH_OPTION(poptions, opt)
		if(!opt->positional)
			num++;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	memcpy(new_options, &common_opts, sizeof(struct option) * num_cmn);
	nopt = new_options + num_cmn;

	FOR_EACH_OPTION(poptions, opt) {
		if (opt->positional)
			continue;
		nopt->has_arg = opt_needs_arg(opt) ? required_argument : no_argument;
		nopt->name = opt->name;
		nopt->val = opt->short_opt;
		nopt++;
		if (opt->short_opt) {
			*(c++) = opt->short_opt;
			if (opt_needs_arg(opt))
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

static struct prog_option *find_opt(struct prog_option *all_opts,
				       int optchar)
{
	struct prog_option *opt;

	FOR_EACH_OPTION(all_opts, opt)
		if (opt->short_opt == optchar)
			return opt;
	return NULL;
}

static int set_opt(void *cfg, struct prog_option *all_opts,
		   int optchar, char *optarg)
{
	struct prog_option *opt;
	int ret;

	if (!cfg)
		return -EFAULT;

	opt = find_opt(all_opts, optchar);
	if (!opt)
		return -1;

	ret = handlers[opt->type].func(optarg, (cfg + opt->cfg_offset),
				       opt->typearg);
	if (!ret)
		opt->was_set = true;
	return ret;
}

static int set_pos_opt(void *cfg, struct prog_option *all_opts, char *optarg)
{
	struct prog_option *o, *opt = NULL;
	int ret;

	FOR_EACH_OPTION(all_opts, o) {
		if (o->positional && (!o->was_set || opt_is_multi(o))) {
			opt = o;
			break;
		}
	}

	if (!opt)
		return -ENOENT;

	ret = handlers[opt->type].func(optarg, (cfg + opt->cfg_offset),
				       opt->typearg);
	if (!ret)
		opt->was_set = true;
	return ret;
}

int parse_cmdline_args(int argc, char **argv,
		       struct prog_option *poptions,
		       void *cfg, const char *prog, const char *doc,
		       const void *defaults)
{
	struct prog_option *opt_iter;
	struct option *long_options;
	bool full_help = false;
	int i, opt, err = 0;
	int longindex = 0;
	char *optstring;

	if (prog_options_to_options(poptions, &long_options, &optstring)) {
		pr_warn("Unable to malloc()\n");
		return -ENOMEM;
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'h':
			usage(prog, doc, poptions, true);
			err = EXIT_FAILURE;
			goto out;
		case 'v':
			increase_log_level();
			break;
		default:
			if (set_opt(cfg, poptions, opt, optarg)) {
				usage(prog, doc, poptions, full_help);
				err = EXIT_FAILURE;
				goto out;
			}
			break;
		}
	}

	for (i = optind; i < argc; i++) {
		if (set_pos_opt(cfg, poptions, argv[i])) {
			usage(prog, doc, poptions, full_help);
			err = EXIT_FAILURE;
			goto out;
		}
	}

	FOR_EACH_OPTION(poptions, opt_iter) {
		if (opt_iter->was_set)
			continue;
		if (opt_iter->required) {
			if (opt_iter->positional)
				pr_warn("Missing required parameter %s\n",
					opt_iter->metavar ?: opt_iter->name);
			else
				pr_warn("Missing required option '--%s'\n",
					opt_iter->name);
			usage(prog, doc, poptions, full_help);
			err = EXIT_FAILURE;
			goto out;
		} else if (defaults) {
			void *dst = cfg + opt_iter->cfg_offset;
			const void *src = defaults + opt_iter->cfg_offset;

			memcpy(dst, src, opt_iter->opt_size);
		}
	}
out:
	free(long_options);
	free(optstring);

	return err;
}

int dispatch_commands(const char *argv0, int argc, char **argv,
		      const struct prog_command *cmds, size_t cfg_size,
		      const char *prog_name)
{
	const struct prog_command *c, *cmd = NULL;
	char pin_root_path[PATH_MAX];
	int ret = EXIT_FAILURE, err;
	char namebuf[100];
	void *cfg;

	for (c = cmds; c->name; c++) {
		if (is_prefix(argv0, c->name)) {
			cmd = c;
			break;
		}
	}

	if (!cmd) {
		pr_warn("Command '%s' is unknown, try '%s help'.\n",
			argv0, prog_name);
		return EXIT_FAILURE;
	}

	if (cmd->no_cfg)
		return cmd->func(NULL, NULL);

	cfg = malloc(cfg_size);
	if (!cfg) {
		pr_warn("Couldn't allocate memory\n");
		return EXIT_FAILURE;
	}

	snprintf(namebuf, sizeof(namebuf), "%s %s", prog_name, cmd->name);
	err = parse_cmdline_args(argc, argv, cmd->options, cfg, namebuf,
				 cmd->doc, cmd->default_cfg);
	if (err)
		goto out;

	err = get_bpf_root_dir(pin_root_path, sizeof(pin_root_path), prog_name);
	if (err)
		goto out;

	err = check_bpf_environ(pin_root_path);
	if (err)
		goto out;

	if (prog_lock_get(prog_name))
		goto out;

	ret = cmd->func(cfg, pin_root_path);
	prog_lock_release(0);
out:
	free(cfg);
	return ret;
}
