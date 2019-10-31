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

#include "params.h"

int verbose = 1;

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

static const struct opthandler {
	int (*func)(const struct option_wrapper *opt, void *cfg, char *optarg);
} handlers[__OPT_MAX] = {
			 {NULL},
			 {handle_bool},
			 {handle_string},
			 {handle_u32},
			 {handle_macaddr},
			 {handle_flags}
};

static void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		if (long_options[i].required != required)
			continue;

		if (long_options[i].option.val > 64) /* ord('A') = 65 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);
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
	printf("Usage: %s [options]\n", prog_name);

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

static const struct option_wrapper *
find_opt(const struct option_wrapper *all_opts,
	 int optchar)
{
	while (all_opts->option.name != 0) {
		if (all_opts->option.val == optchar)
			return all_opts;
		all_opts++;
	}
	return NULL;
}

static int set_opt(void *cfg, const struct option_wrapper *all_opts,
		   int optchar, char *optarg)
{
	const struct option_wrapper *opt;

	opt = find_opt(all_opts, optchar);
	if (!opt)
		return -1;

	return handlers[opt->type].func(opt, cfg, optarg);
}

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        void *cfg, const char *prog, const char *doc)
{
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
out:
	free(long_options);
	free(optstring);
	if (err)
		exit(err);
}
