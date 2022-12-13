#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/err.h>
#include <linux/if_link.h>

#include "params.h"
#include "logging.h"
#include "util.h"
#include "xdp_sample.h"


#define PROG_NAME "test-tool"


#ifndef HAVE_LIBBPF_BPF_OBJECT__NEXT_PROGRAM
static struct bpf_program *bpf_object__next_program(const struct bpf_object *obj,
  						    struct bpf_program *prog)
{
  	return bpf_program__next(prog, obj);
}
#endif


struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {"unspecified", XDP_MODE_UNSPEC},
       {NULL, 0}
};


static const struct loadopt {
	bool help;
	enum xdp_attach_mode mode;
	struct iface iface;
	char *filename;
} defaults_load = {
	.mode = XDP_MODE_NATIVE
};


static struct bpf_object *open_bpf_obj(const char *filename,
				       struct bpf_object_open_opts *opts)
{
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open_file(filename, opts);
	err = libbpf_get_error(obj);
	if (err) {
		if (err == -ENOENT)
			pr_debug(
				"Couldn't load the eBPF program (libbpf said 'no such file').\n"
				"Maybe the program was compiled with a too old "
				"version of LLVM (need v9.0+)?\n");
		return ERR_PTR(err);
	}

	return obj;
}

static int do_xdp_attach(int ifindex, int prog_fd, int old_fd, __u32 xdp_flags)
{
#ifdef HAVE_LIBBPF_BPF_XDP_ATTACH
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts,
		    .old_prog_fd = old_fd);
	return bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &opts);
#else
	DECLARE_LIBBPF_OPTS(bpf_xdp_set_link_opts, opts, .old_fd = old_fd);
	return bpf_set_link_xdp_fd_opts(ifindex, prog_fd, xdp_flags, old_fd ? &opts : NULL);
#endif
}

int do_load(const void *cfg, __unused const char *pin_root_path)
{
	const struct loadopt *opt = cfg;
	struct bpf_program *bpf_prog;
	char errmsg[STRERR_BUFSIZE];
  	struct bpf_object *obj;
	int err = EXIT_SUCCESS;
	int xdp_flags;
	int prog_fd;

	silence_libbpf_logging();
retry:
	obj = open_bpf_obj(opt->filename, NULL);

	if (IS_ERR(obj)) {
		err = PTR_ERR(obj);

		if (err == -EPERM && !double_rlimit())
			goto retry;

		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("ERROR: Couldn't open file '%s': %s\n",
			opt->filename, errmsg);
		goto out;
	}

	err = bpf_object__load(obj);
  	if (err) {

		if (err == -EPERM && !double_rlimit()) {
			bpf_object__close(obj);
			goto retry;
		}

		libbpf_strerror(err, errmsg, sizeof(errmsg));
  		pr_warn("ERROR: Can't load eBPF object: %s(%d)\n",
			errmsg, err);
		goto out;
	}

	bpf_prog = bpf_object__next_program(obj, NULL);
	if (!bpf_prog) {
  		pr_warn("ERROR: Couldn't find xdp program in bpf object!\n");
		err = -ENOENT;
		goto out;
  	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd < 0) {
		err = prog_fd;
		libxdp_strerror(err, errmsg, sizeof(errmsg));
  		pr_warn("ERROR: Couldn't find xdp program's file descriptor: %s\n",
			errmsg);
		goto out;
  	}

	xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	switch (opt->mode) {
  	case XDP_MODE_SKB:
  		xdp_flags |= XDP_FLAGS_SKB_MODE;
  		break;
  	case XDP_MODE_NATIVE:
  		xdp_flags |= XDP_FLAGS_DRV_MODE;
  		break;
  	case XDP_MODE_HW:
  		xdp_flags |= XDP_FLAGS_HW_MODE;
  		break;
  	case XDP_MODE_UNSPEC:
  		break;
  	}
	err = do_xdp_attach(opt->iface.ifindex, prog_fd, 0, xdp_flags);
	if (err < 0) {
 		pr_info("ERROR: Failed attaching XDP program to ifindex %d: %s\n",
			opt->iface.ifindex, strerror(-err));

  		switch (-err) {
  		case EBUSY:
  		case EEXIST:
  			pr_info("XDP already loaded on device.\n");
  			break;
  		case EOPNOTSUPP:
  			pr_info("XDP mode not supported; try using SKB mode.\n");
  			break;
  		default:
 			break;
  		}
		goto out;
  	}
out:
	return err;
}


static struct prog_option load_options[] = {
	DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	DEFINE_OPTION("filename", OPT_STRING, struct loadopt, filename,
		      .positional = true,
		      .metavar = "<filename>",
		      .required = true,
		      .help = "Load program from <filename>"),
	END_OPTIONS
};

enum probe_action {
        PROBE_CPUMAP_PROGRAM,
};

struct enum_val probe_actions[] = {
       {"cpumap-prog", PROBE_CPUMAP_PROGRAM},
       {NULL, 0}
};

static const struct probeopt {
	enum probe_action action;
} defaults_probe = {};

int do_probe(const void *cfg, __unused const char *pin_root_path)
{
        const struct probeopt *opt = cfg;
        bool res = false;

	switch (opt->action) {
	case PROBE_CPUMAP_PROGRAM:
		res = sample_probe_cpumap_compat();
		break;
        default:
                return EXIT_FAILURE;
	}

        pr_debug("Probing for %s: %s\n",
                 probe_actions[opt->action].name,
                 res ? "Supported" : "Unsupported");

        return res ? EXIT_SUCCESS : EXIT_FAILURE;
}


static struct prog_option probe_options[] = {
	DEFINE_OPTION("action", OPT_ENUM, struct probeopt, action,
		      .positional = true,
		      .metavar = "<action>",
		      .required = true,
                      .typearg = probe_actions,
		      .help = "Probe for <action>"),
	END_OPTIONS
};


int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: test-tool COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load          - load an XDP program on an interface\n"
		"       probe         - probe for kernel features\n"
		"       help          - show this help message\n"
		"\n"
		"Use 'test-tool COMMAND --help' to see options for each command\n");
	return -1;
}


static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load an XDP program on an interface"),
	DEFINE_COMMAND(probe, "Probe for kernel features"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};


union all_opts {
	struct loadopt load;
	struct probeopt probe;
};


int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);
	return do_help(NULL, NULL);
}
