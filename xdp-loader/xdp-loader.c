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
	bool force;
	enum xdp_attach_mode mode;
} defaults_load = {
	.mode = XDP_MODE_UNSPEC
};

struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {NULL, 0}
};


static struct prog_option load_options[] = {
	DEFINE_OPTION("force", OPT_BOOL, struct loadopt, force,
		      .short_opt = 'F',
		      .help = "Force loading of XDP program"),
	DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default unspecified"),
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

int load_multiprog(const struct loadopt *opt)
{
	size_t num_progs = opt->filenames.num_strings;
	struct xdp_program **progs, *p;
	struct xdp_multiprog *mp;
	int err = 0, i;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = opt->pin_path);

	progs = calloc(sizeof(*progs), num_progs);
	if (!progs) {
		pr_warn("Couldn't allocate memory\n");
		return EXIT_FAILURE;
	}
	memset(progs, 0, sizeof(*progs) * num_progs);

	for (i = 0; i < num_progs; i++) {
		p = xdp_program__open_file(opt->filenames.strings[i],
						  opt->section_name, &opts);
		if (IS_ERR(p)) {
			err = PTR_ERR(p);
			pr_warn("Couldn't open file '%s': %s",
				opt->filenames.strings[i], strerror(-err));
			goto out;
		}
		progs[i] = p;
	}

	mp = xdp_multiprog__generate(progs, num_progs);

	if (IS_ERR(mp)) {
		err = PTR_ERR(mp);
		pr_warn("Failed to load program: %s\n", strerror(-err));
		goto out;
	}

	err = xdp_multiprog__pin(mp);
	if (err) {
		pr_warn("Failed to pin program: %s\n", strerror(-err));
		goto out_free_mp;
	}

	err = xdp_multiprog__attach(mp, opt->iface.ifindex,
				    opt->force, opt->mode);
	if (err) {
		pr_warn("Failed to attach program: %s\n", strerror(-err));
		goto out_free_mp;
	}

out_free_mp:
	xdp_multiprog__free(mp);
out:
	for (i = 0; i < num_progs; i++)
		if (progs[i])
			xdp_program__free(progs[i]);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

int do_load(const void *cfg, const char *pin_root_path)
{
	const struct loadopt *opt = cfg;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct xdp_program *xdp_prog;
	char errmsg[STRERR_BUFSIZE];
	int err = EXIT_SUCCESS;
	const char *filename;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = opt->pin_path);

	if (!opt->filenames.num_strings) {
		pr_warn("Need at least one filename to load\n");
		return EXIT_FAILURE;
	} else if (opt->filenames.num_strings > 1) {
		return load_multiprog(opt);
	}
	filename = opt->filenames.strings[0];

	pr_debug("Loading file '%s' on interface '%s'.\n",
		 filename, opt->iface.ifname);

	/* libbpf spits out a lot of unhelpful error messages while loading.
	 * Silence the logging so we can provide our own messages instead; this
	 * is a noop if verbose logging is enabled.
	 */
	silence_libbpf_logging();

retry:

	obj = bpf_object__open_file(filename, &opts);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't load BPF program: %s\n", errmsg);
		obj = NULL;
		goto out;
	}

	xdp_prog = xdp_program__from_bpf_obj(obj, opt->section_name);
	if (IS_ERR(xdp_prog)) {
		libbpf_strerror(PTR_ERR(xdp_prog), errmsg, sizeof(errmsg));
		pr_warn("Couldn't get XDP program: %s\n", errmsg);
		goto out;
	}
	xdp_program__print_chain_call_actions(xdp_prog, errmsg, sizeof(errmsg));
	pr_debug("XDP program run prio: %d. Chain call actions: %s\n",
		 xdp_program__run_prio(xdp_prog), errmsg);

	if (!opt->pin_path) {
		struct bpf_map *map;

		bpf_object__for_each_map(map, obj)
			bpf_map__set_pin_path(map, NULL);
	}

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
		bpf_program__set_expected_attach_type(prog, BPF_PROG_TYPE_XDP);
	}

	err = bpf_object__load(obj);
	if (err) {
		if (err == -EPERM) {
			pr_debug("Permission denied when loading eBPF object; "
				 "raising rlimit and retrying\n");

			if (!double_rlimit()) {
				bpf_object__close(obj);
				goto retry;
			}
		}

		libbpf_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("Couldn't load eBPF object: %s(%d)\n", errmsg, err);
		goto out;
	}

	err = attach_xdp_program(obj, opt->section_name, &opt->iface, opt->force,
				 opt->mode, opt->pin_path);
	if (err) {
		pr_warn("Couldn't attach XDP program on iface '%s'\n",
			opt->iface.ifname);
		goto out;
	}

out:
	if (obj)
		bpf_object__close(obj);
	return err;
}

static int remove_iface_program(const struct iface *iface,
				const struct bpf_prog_info *info,
				enum xdp_attach_mode mode, void *arg)
{
	char *pin_root_path = arg;
	int err;

	err = detach_xdp_program(iface, pin_root_path);
	if (err) {
		pr_warn("Removing XDP program on iface %s failed (%d): %s\n",
			iface->ifname, -err, strerror(-err));
	}
	return err;
}


static const struct unloadopt {
	bool all;
	struct iface iface;
} defaults_unload = {};

static struct prog_option unload_options[] = {
	DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .help = "Unload from device <ifname>"),
	DEFINE_OPTION("all", OPT_BOOL, struct unloadopt, all,
		      .short_opt = 'a',
		      .help = "Unload from all interfaces"),
	END_OPTIONS
};

int do_unload(const void *cfg, const char *pin_root_path)
{
	const struct unloadopt *opt = cfg;
	struct bpf_prog_info info;
	struct xdp_multiprog *mp;
	int err = EXIT_SUCCESS;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .pin_root_path = pin_root_path);

	if (opt->all) {
		pr_debug("Removing XDP programs from all interfaces\n");
		err = iterate_iface_programs_all(pin_root_path, remove_iface_program,
						 (void *)pin_root_path);
		goto out;
	}

	if (!opt->iface.ifindex) {
		pr_warn("Must specify ifname or --all\n");
		err = EXIT_FAILURE;
		goto out;
	}

	mp = xdp_multiprog__get_from_ifindex(opt->iface.ifindex);
	if (!IS_ERR_OR_NULL(mp)) {
		err = xdp_multiprog__unpin(mp);
		xdp_multiprog__free(mp);
		goto out;
	}

	err = get_loaded_program(&opt->iface, NULL, &info);
	if (err) {
		pr_warn("No XDP program loaded on %s\n", opt->iface.ifname);
		err = EXIT_FAILURE;
		goto out;
	}

	err = remove_iface_program(&opt->iface, &info, false, (void *)pin_root_path);
	if (err)
		goto out;

out:
	return err;
}

static struct prog_option status_options[] = {
	END_OPTIONS
};

int print_iface_status(const struct iface *iface, const struct bpf_prog_info *info,
		       enum xdp_attach_mode mode, void *arg)
{
	struct xdp_program *xdp_prog;
	struct xdp_multiprog *mp;
	char tag[BPF_TAG_SIZE*2+1];
	char buf[STRERR_BUFSIZE];
	int i, err;

	for (i = 0; i < BPF_TAG_SIZE; i++) {
		sprintf(&tag[i*2], "%02x", info->tag[i]);
	}
	tag[BPF_TAG_SIZE*2] = '\0';

	xdp_prog = xdp_program__from_id(info->id);
	if (IS_ERR(xdp_prog)) {
		err = PTR_ERR(xdp_prog);
		libbpf_strerror(err, buf, sizeof(buf));
		printf("err: %s\n", buf);
		return err;
	}
	printf("%-16s %-5s %-16s %-8s %-4d %-17s\n",
	       iface->ifname,
	       "",
	       info->name,
	       get_enum_name(xdp_modes, mode),
	       info->id, tag);

	mp = xdp_multiprog__get_from_ifindex(iface->ifindex);
	if (!IS_ERR_OR_NULL(mp)) {
		struct xdp_program *sub_prog;

		for (sub_prog = xdp_multiprog__next_prog(NULL, mp);
		     sub_prog;
		     sub_prog = xdp_multiprog__next_prog(sub_prog, mp)) {

			const uint8_t *raw_tag = xdp_program__tag(sub_prog);

			xdp_program__print_chain_call_actions(xdp_prog, buf,
							      sizeof(buf));

			for (i = 0; i < BPF_TAG_SIZE; i++)
				sprintf(&tag[i*2], "%02x", raw_tag[i]);

			tag[BPF_TAG_SIZE*2] = '\0';

			printf("%-16s %-5d %-16s %-8s %-4u %-17s %s\n",
			       " =>", xdp_program__run_prio(sub_prog),
			       xdp_program__name(sub_prog),
			       "", xdp_program__id(sub_prog),
			       tag, buf);
		}

		xdp_multiprog__free(mp);
	}

	return 0;
}

int do_status(const void *cfg, const char *pin_root_path)
{
	int err = EXIT_SUCCESS;

	printf("CURRENT XDP PROGRAM STATUS:\n\n");
	printf("%-16s %-5s %-16s Mode     ID   %-17s %s\n",
	       "Interface", "Prio", "Program name", "Tag", "Chain actions");
	printf("-------------------------------------------------------------------------------------\n");

	err = iterate_iface_programs_all(pin_root_path, print_iface_status, NULL);
	printf("\n");

	return err;
}

int do_help(const void *cfg, const char *pin_root_path)
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
	{.name = "help", .func = do_help, .no_cfg = true},
	END_COMMANDS
};

union all_opts {
	struct loadopt load;
	struct unloadopt unload;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc-1, argv+1,
					 cmds, sizeof(union all_opts),
					 PROG_NAME);

	return do_help(NULL, NULL);
}
