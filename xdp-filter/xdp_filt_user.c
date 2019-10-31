/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "params.h"
#include "logging.h"
#include "util.h"
#include "common_kern_user.h"
#include "prog_features.h"

#define NEED_RLIMIT (10*1024*1024) /* 10 Mbyte */

struct installopt {
	bool help;
	struct iface iface;
	int features;
};

struct flag_val install_features[] = {
	{"tcp", FEAT_TCP},
	{"udp", FEAT_UDP},
	{"ipv6", FEAT_IPV6},
	{"ipv4", FEAT_IPV4},
	{"ethernet", FEAT_ETHERNET},
	{"all", FEAT_ALL},
	{}
};

static char *find_progname(__u32 features)
{
	struct prog_feature *feat;

	if (!features)
		return NULL;

	for (feat = prog_features; feat->prog_name; feat++) {
		if ((ntohl(feat->features) & features) == features)
			return feat->prog_name;
	}
	return NULL;
}

static struct option_wrapper install_options[] = {
	DEFINE_OPTION('h', "help", no_argument, false, OPT_HELP, NULL,
		      "Show help", "",
		      struct installopt, help),
	DEFINE_OPTION('v', "verbose", no_argument, false, OPT_VERBOSE, NULL,
		      "Enable verbose logging", "",
		      struct installopt, help),
	DEFINE_OPTION('d', "dev", required_argument, true, OPT_IFNAME, NULL,
		      "Install on device <ifname>", "<ifname>",
		      struct installopt, iface),
	DEFINE_OPTION('f', "features", optional_argument, true,
		      OPT_FLAGS, install_features,
		      "Enable features <feats>", "<feats>",
		      struct installopt, features),
	END_OPTIONS
};

int do_install(int argc, char **argv)
{
	struct installopt opt = {};
	struct bpf_object *obj = NULL;
	char *progname;
	int err = EXIT_SUCCESS;

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, install_options, &opt,
			   "xdp-filter install",
			   "Install xdp-filter on an interface");

	progname = find_progname(opt.features);
	if (!progname) {
		pr_warn("Couldn't find an eBPF program with the requested feature set!\n");
		return EXIT_FAILURE;
	}

	pr_debug("Found prog '%s' matching feature set to be installed on interface '%s'.\n",
		 progname, opt.iface.ifname);

	err = check_bpf_environ(NEED_RLIMIT);
	if (err)
		goto out;

	obj = bpf_object__open_file(progname, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err)
		goto out;

out:
	if (obj)
		bpf_object__close(obj);
	return err;
}

int do_add_port(int argc, char **argv)
{
	return EXIT_FAILURE;
}

int do_add_ip(int argc, char **argv)
{
	return EXIT_FAILURE;
}

int do_add_ether(int argc, char **argv)
{
	return EXIT_FAILURE;
}

int do_status(int argc, char **argv)
{
	return EXIT_FAILURE;
}

int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: xdp-filter { COMMAND | help } [OPTIONS]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       install     - install xdp-filter on an interface\n"
		"       port        - add a port to the blacklist\n"
		"       ip          - add an IP address to the blacklist\n"
		"       ether       - add an Ethernet MAC address to the blacklist\n"
		"       status      - show current xdp-filter status\n"
		"\n"
		"Use 'xdp-filter <COMMAND> --help' to see options for each command\n");
	exit(-1);
}


static const struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
} cmds[] = {
	{ "install",	do_install },
	{ "port",	do_add_port },
	{ "ip",	do_add_ip },
	{ "ether",	do_add_ether },
	{ "status",	do_status },
	{ "help",	do_help },
	{ 0 }
};

static int do_cmd(const char *argv0, int argc, char **argv)
{
	const struct cmd *c;

	for (c = cmds; c->cmd; ++c) {
		if (is_prefix(argv0, c->cmd))
			return -(c->func(argc, argv));
	}

	fprintf(stderr, "Object \"%s\" is unknown, try \"xdp-filt help\".\n", argv0);
	return EXIT_FAILURE;
}

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	init_logging();

	if (argc > 1)
		return do_cmd(argv[1], argc-1, argv+1);
	return EXIT_FAILURE;
}
