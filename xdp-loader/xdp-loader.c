/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <linux/err.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#define PROG_NAME "xdp-loader"

static const struct loadopt {
	bool help;
	struct iface iface;
	struct multistring filenames;
	char *pin_path;
	char *section_name;
	enum xdp_attach_mode mode;
} defaults_load = {
	.mode = XDP_MODE_NATIVE
};

struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {"unspecified", XDP_MODE_UNSPEC},
       {NULL, 0}
};


static struct prog_option load_options[] = {
	DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("pin-path", OPT_STRING, struct loadopt, pin_path,
		      .short_opt = 'p',
		      .help = "Path to pin maps under (must be in bpffs)."),
	DEFINE_OPTION("section", OPT_STRING, struct loadopt, section_name,
		      .metavar = "<section>",
		      .short_opt = 's',
		      .help = "ELF section name of program to load (default: first in file)."),
	DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	DEFINE_OPTION("filenames", OPT_MULTISTRING, struct loadopt, filenames,
		      .positional = true,
		      .metavar = "<filenames>",
		      .required = true,
		      .help = "Load programs from <filenames>"),
	END_OPTIONS
};

int do_load(const void *cfg, __unused const char *pin_root_path)
{
	const struct loadopt *opt = cfg;
	struct xdp_program **progs, *p;
	char errmsg[STRERR_BUFSIZE];
	int err = EXIT_SUCCESS;
	size_t num_progs, i;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = opt->pin_path);

	num_progs = opt->filenames.num_strings;
	if (!num_progs) {
		pr_warn("Need at least one filename to load\n");
		return EXIT_FAILURE;
	} else if (num_progs > 1 && opt->mode == XDP_MODE_HW) {
		pr_warn("Cannot attach multiple programs in HW mode\n");
		return EXIT_FAILURE;
	}

	progs = calloc(num_progs, sizeof(*progs));
	if (!progs) {
		pr_warn("Couldn't allocate memory\n");
		return EXIT_FAILURE;
	}

	pr_debug("Loading %zu files on interface '%s'.\n",
		 num_progs, opt->iface.ifname);

	/* libbpf spits out a lot of unhelpful error messages while loading.
	 * Silence the logging so we can provide our own messages instead; this
	 * is a noop if verbose logging is enabled.
	 */
	silence_libbpf_logging();

retry:
	for (i = 0; i < num_progs; i++) {
		p = progs[i];
		if (p)
			xdp_program__close(p);

		p = xdp_program__open_file(opt->filenames.strings[i],
					   opt->section_name, &opts);

		if (IS_ERR(p)) {
			err = PTR_ERR(p);

			if (err == -EPERM && !double_rlimit())
				goto retry;

			libxdp_strerror(err, errmsg, sizeof(errmsg));
			pr_warn("Couldn't open file '%s': %s\n",
				opt->filenames.strings[i], errmsg);
			goto out;
		}

		xdp_program__print_chain_call_actions(p, errmsg, sizeof(errmsg));
		pr_debug("XDP program %zu: Run prio: %d. Chain call actions: %s\n",
			 i, xdp_program__run_prio(p), errmsg);

		if (!opt->pin_path) {
			struct bpf_map *map;

			bpf_object__for_each_map(map, xdp_program__bpf_obj(p)) {
				err = bpf_map__set_pin_path(map, NULL);
				if (err) {
					pr_warn("Error clearing map pin path: %s\n",
						strerror(-err));
					goto out;
				}
			}
		}

		progs[i] = p;
	}

	err = xdp_program__attach_multi(progs, num_progs,
					opt->iface.ifindex, opt->mode, 0);
	if (err) {
		if (err == -EPERM && !double_rlimit())
			goto retry;

		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't attach XDP program on iface '%s': %s(%d)\n",
			opt->iface.ifname, errmsg, err);
		goto out;
	}

out:
	for (i = 0; i < num_progs; i++)
		if (progs[i])
			xdp_program__close(progs[i]);
	free(progs);
	return err;
}

static const struct unloadopt {
	bool all;
	__u32 prog_id;
	struct iface iface;
} defaults_unload = {};

static struct prog_option unload_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .help = "Unload from device <ifname>"),
	DEFINE_OPTION("id", OPT_U32, struct unloadopt, prog_id,
		      .metavar = "<id>",
		      .short_opt = 'i',
		      .help = "Unload program with id <id>"),
	DEFINE_OPTION("all", OPT_BOOL, struct unloadopt, all,
		      .short_opt = 'a',
		      .help = "Unload all programs from interface"),
	END_OPTIONS
};

int do_unload(const void *cfg, __unused const char *pin_root_path)
{
	const struct unloadopt *opt = cfg;
	struct xdp_multiprog *mp = NULL;
	enum xdp_attach_mode mode;
	int err = EXIT_FAILURE;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = pin_root_path);

	if (!opt->all && !opt->prog_id) {
		pr_warn("Need prog ID or --all\n");
		goto out;
	}

	if (!opt->iface.ifindex) {
		pr_warn("Must specify ifname\n");
		goto out;
	}

	mp = xdp_multiprog__get_from_ifindex(opt->iface.ifindex);
	if (IS_ERR_OR_NULL(mp)) {
		pr_warn("No XDP program loaded on %s\n", opt->iface.ifname);
		mp = NULL;
		goto out;
	}

	if (opt->all) {
		err = xdp_multiprog__detach(mp);
		if (err) {
			pr_warn("Unable to detach XDP program: %s\n",
				strerror(-err));
			goto out;
		}
	} else {
		struct xdp_program *prog = NULL;

		while ((prog = xdp_multiprog__next_prog(prog, mp))) {
			if (xdp_program__id(prog) == opt->prog_id) {
				mode = xdp_multiprog__attach_mode(mp);
				goto found;
			}
		}

		if (xdp_multiprog__is_legacy(mp)) {
			prog = xdp_multiprog__main_prog(mp);
			if (xdp_program__id(prog) == opt->prog_id) {
				mode = xdp_multiprog__attach_mode(mp);
				goto found;
			}
		}

		prog = xdp_multiprog__hw_prog(mp);
		if (xdp_program__id(prog) == opt->prog_id) {
			mode = XDP_MODE_HW;
			goto found;
		}

		pr_warn("Program with ID %u not loaded on %s\n",
			opt->prog_id, opt->iface.ifname);
		err = -ENOENT;
		goto out;

found:
		pr_debug("Detaching XDP program with ID %u from %s\n",
			 xdp_program__id(prog), opt->iface.ifname);
		err = xdp_program__detach(prog, opt->iface.ifindex, mode, 0);
		if (err) {
			pr_warn("Unable to detach XDP program: %s\n",
				strerror(-err));
			goto out;
		}
	}

out:
	xdp_multiprog__close(mp);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static struct prog_option status_options[] = { END_OPTIONS };

static char *print_bpf_tag(char buf[BPF_TAG_SIZE * 2 + 1],
			   const unsigned char tag[BPF_TAG_SIZE])
{
	int i;

	for (i = 0; i < BPF_TAG_SIZE; i++)
		sprintf(&buf[i * 2], "%02x", tag[i]);
	buf[BPF_TAG_SIZE * 2] = '\0';
	return buf;
}

int print_iface_status(const struct iface *iface,
		       const struct xdp_multiprog *mp, __unused void *arg)
{
	struct xdp_program *prog, *dispatcher, *hw_prog;
	char tag[BPF_TAG_SIZE * 2 + 1];
	char buf[STRERR_BUFSIZE];
	int err;

	if (!mp) {
		printf("%-16s <no XDP program>\n", iface->ifname);
		return 0;
	}

	hw_prog = xdp_multiprog__hw_prog(mp);
	if (hw_prog) {
		printf("%-16s %-5s %-16s %-8s %-4d %-17s\n",
		       iface->ifname,
		       "",
		       xdp_program__name(hw_prog),
		       get_enum_name(xdp_modes, XDP_MODE_HW),
		       xdp_program__id(hw_prog),
		       print_bpf_tag(tag, xdp_program__tag(hw_prog)));
	}

	dispatcher = xdp_multiprog__main_prog(mp);
	if (dispatcher) {
		printf("%-16s %-5s %-16s %-8s %-4d %-17s\n",
		iface->ifname,
		"",
		xdp_program__name(dispatcher),
		get_enum_name(xdp_modes, xdp_multiprog__attach_mode(mp)),
		xdp_program__id(dispatcher),
		print_bpf_tag(tag, xdp_program__tag(dispatcher)));


		for (prog = xdp_multiprog__next_prog(NULL, mp);
		     prog;
		     prog = xdp_multiprog__next_prog(prog, mp)) {

			err = xdp_program__print_chain_call_actions(prog, buf,
								    sizeof(buf));
			if (err)
				return err;

			printf("%-16s %-5d %-16s %-8s %-4u %-17s %s\n",
			       " =>", xdp_program__run_prio(prog),
			       xdp_program__name(prog),
			       "", xdp_program__id(prog),
			       print_bpf_tag(tag, xdp_program__tag(prog)),
			       buf);
		}
	}

	return 0;
}

int do_status(__unused const void *cfg, __unused const char *pin_root_path)
{
	int err = EXIT_SUCCESS;

	printf("CURRENT XDP PROGRAM STATUS:\n\n");
	printf("%-16s %-5s %-16s Mode     ID   %-17s %s\n",
	       "Interface", "Prio", "Program name", "Tag", "Chain actions");
	printf("-------------------------------------------------------------------------------------\n");

	err = iterate_iface_multiprogs(print_iface_status, NULL);
	printf("\n");

	return err;
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-loader COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load        - load an XDP program on an interface\n"
		"       unload      - unload an XDP program from an interface\n"
		"       status      - show current XDP program status\n"
		"       help        - show this help message\n"
		"\n"
		"Use 'xdp-loader COMMAND --help' to see options for each command\n");
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load an XDP program on an interface"),
	DEFINE_COMMAND(unload, "Unload an XDP program from an interface"),
	DEFINE_COMMAND_NODEF(status, "Show XDP program status"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct loadopt load;
	struct unloadopt unload;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME);

	return do_help(NULL, NULL);
}
