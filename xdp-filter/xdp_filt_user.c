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
#include "libbpf.h"
#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "params.h"
#include "logging.h"
#include "util.h"
#include "common_kern_user.h"
#include "prog_features.h"

#define NEED_RLIMIT (20*1024*1024) /* 10 Mbyte */
#define BPFFS_DIR "xdp-filter"

struct installopt {
	bool help;
	struct iface iface;
	int features;
	bool force;
	bool skb_mode;
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

struct flag_val map_flags[] = {
	{"src", MAP_FLAG_SRC},
	{"dst", MAP_FLAG_DST},
	{"tcp", MAP_FLAG_TCP},
	{"udp", MAP_FLAG_UDP},
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

int map_get_counter_flags(int fd, void *key, __u64 *counter, __u8 *flags)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__u64 sum_ctr = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, key, values)) != 0)
		return -ENOENT;

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		__u8 flg = values[i] & MAP_FLAGS;

		if (!flg)
			return -ENOENT; /* not set */
		*flags = flg;
		sum_ctr += values[i] >> COUNTER_SHIFT;
	}
	*counter = sum_ctr;

	return 0;
}


static struct option_wrapper install_options[] = {
	DEFINE_OPTION('h', "help", no_argument, false, OPT_HELP, NULL,
		      "Show help", "",
		      struct installopt, help),
	DEFINE_OPTION('v', "verbose", no_argument, false, OPT_VERBOSE, NULL,
		      "Enable verbose logging", "",
		      struct installopt, help),
	DEFINE_OPTION('F', "force", no_argument, false, OPT_BOOL, NULL,
		      "Force loading of XDP program", "",
		      struct installopt, force),
	DEFINE_OPTION('s', "skb-mode", no_argument, false, OPT_BOOL, NULL,
		      "Load XDP program in SKB (generic) mode", "",
		      struct installopt, skb_mode),
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
	char *progname, pin_root_path[PATH_MAX];
	struct bpf_object *obj = NULL;
	struct installopt opt = {};
	struct bpf_program *prog;
	int err = EXIT_SUCCESS;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = pin_root_path);

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

	err = get_bpf_root_dir(pin_root_path, sizeof(pin_root_path), BPFFS_DIR);
	if (err)
		goto out;

	obj = bpf_object__open_file(progname, &opts);
	err = libbpf_get_error(obj);
	if (err) {
		obj = NULL;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err)
		goto out;

	prog = bpf_program__next(NULL, obj);
	if (!prog) {
		pr_warn("Couldn't find an eBPF program to attach. This is a bug!\n");
		goto out;
	}

	err = load_xdp_program(prog, opt.iface.ifindex, opt.force, opt.skb_mode);
	if (err) {
		pr_warn("Couldn't attach XDP program on iface '%s'\n",
			opt.iface.ifname);
		goto out;
	}

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
	char pin_root_path[PATH_MAX];
	int err = EXIT_SUCCESS, map_fd = -1;

	err = check_bpf_environ(NEED_RLIMIT);
	if (err)
		goto out;

	err = get_bpf_root_dir(pin_root_path, sizeof(pin_root_path), BPFFS_DIR);
	if (err)
		goto out;

	map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME_PORTS));
	if (map_fd >= 0) {
		__u32 map_key = -1, next_key = 0;

		printf("Filtered ports:\n");
		printf("  Port   Type             Hit counter\n");
		FOR_EACH_MAP_KEY(err, map_fd, map_key, next_key)
		{
			char buf[100];
			__u64 counter;
			__u8 flags;

			err = map_get_counter_flags(map_fd, &map_key, &counter, &flags);
			if (err == -ENOENT)
				continue;
			else if (err)
				goto out;

			print_flags(buf, sizeof(buf), map_flags, flags);
			printf("  %-6u %-15s  %llu\n", map_key, buf, counter);
		}
	}

out:
	if (map_fd >= 0)
		close(map_fd);
	return err;
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
