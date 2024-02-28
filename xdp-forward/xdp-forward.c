#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "params.h"
#include "util.h"
#include "logging.h"
#include "compat.h"

#include "xdp-forward.h"
#include "xdp_forward.skel.h"

#define MAX_IFACE_NUM 32
#define PROG_NAME "xdp-forward"

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-forward COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load           - Load the XDP forwarding plane\n"
		"       unload         - Unload the XDP forwarding plane\n"
		"       help           - show this help message\n"
		"\n"
		"Use 'xdp-forward COMMAND --help' to see options for each command\n");
	return -1;
}


struct enum_val xdp_modes[] = { { "native", XDP_MODE_NATIVE },
				{ "skb", XDP_MODE_SKB },
				{ NULL, 0 } };

enum fwd_mode {
	FWD_FIB_DIRECT,
	FWD_FIB_FULL
};

struct enum_val fwd_modes[] = { { "fib-direct", FWD_FIB_DIRECT },
				{ "fib-full", FWD_FIB_FULL },
				{ NULL, 0 } };

static int find_prog(struct iface *iface, bool detach)
{
	struct xdp_program *prog = NULL;
	enum xdp_attach_mode mode;
	struct xdp_multiprog *mp;
	int ret = -ENOENT;

	mp = xdp_multiprog__get_from_ifindex(iface->ifindex);
	if (!mp)
		return ret;

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		goto check;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
	check:
		if (!strcmp(xdp_program__name(prog), "xdp_fwd_fib_full") ||
		    !strcmp(xdp_program__name(prog), "xdp_fwd_fib_direct")) {
			mode = xdp_multiprog__attach_mode(mp);
			ret = 0;
			if (detach) {
				ret = xdp_program__detach(prog, iface->ifindex,
							  mode, 0);
				if (ret)
					pr_warn("Couldn't detach XDP program from interface %s: %s\n",
						iface->ifname,
						strerror(errno));
				break;
			}
		}
	}

	xdp_multiprog__close(mp);
	return ret;
}

int init_tx_port(struct xdp_program *init_prog, int ifindex)
{
	struct port_init_config port_cfg = {.ifindex = ifindex};
	struct xdp_md ctx_in = {
		.data_end = sizeof(port_cfg),
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = &port_cfg,
			    .data_size_in = sizeof(port_cfg), .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in), );
	int nr_cpus = libbpf_num_possible_cpus();
	int err, i;

	for (i = 0; i < nr_cpus; i++) {
		port_cfg.cpu = i;

		err = xdp_program__test_run(init_prog, &opts, 0);
		if (err)
			return -errno;

		if (opts.retval != XDP_PASS)
			return -1;
	}

	return 0;
}

struct load_opts {
	enum fwd_mode fwd_mode;
	enum xdp_attach_mode xdp_mode;
	struct iface *ifaces;
} defaults_load = { .fwd_mode = FWD_FIB_FULL };

struct prog_option load_options[] = {
	DEFINE_OPTION("fwd-mode", OPT_ENUM, struct load_opts, fwd_mode,
		      .short_opt = 'f',
		      .typearg = fwd_modes,
		      .metavar = "<mode>",
		      .help = "Forward mode to run in; see man page. Default fib-full"),
	DEFINE_OPTION("xdp-mode", OPT_ENUM, struct load_opts, xdp_mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<xdp_mode>",
		      .help = "Load XDP program in <xdp_mode>; default native"),
	DEFINE_OPTION("devs", OPT_IFNAME_MULTI, struct load_opts, ifaces,
		      .positional = true,
		      .metavar = "<ifname...>",
		      .min_num = 1,
		      .max_num = MAX_IFACE_NUM,
		      .required = 1,
		      .help = "Redirect from and to devices <ifname...>"),
	END_OPTIONS
};

static int do_load(const void *cfg, __unused const char *pin_root_path)
{
	struct xdp_program *xdp_prog = NULL, *init_prog = NULL;
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	const struct load_opts *opt = cfg;
	struct xdp_forward *skel;
	int ret = EXIT_FAILURE;
	struct iface *iface;

	switch (opt->fwd_mode) {
	case FWD_FIB_FULL:
		opts.prog_name = "xdp_fwd_fib_full";
		break;
	case FWD_FIB_DIRECT:
		opts.prog_name = "xdp_fwd_fib_direct";
		break;
	default:
		goto end;
	}

	skel = xdp_forward__open();
	if (!skel) {
		pr_warn("Failed to load skeleton: %s\n", strerror(errno));
		goto end;
	}

	opts.obj = skel->obj;
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	opts.prog_name = "init_port";
	init_prog = xdp_program__create(&opts);
	if (!init_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	/* We always set the frags support bit: nothing the program does is
	 * incompatible with multibuf, and it's perfectly fine to load a program
	 * with frags support on an interface with a small MTU. We don't risk
	 * setting any flags the kernel will balk at, either, since libxdp will
	 * do the feature probing for us and skip the flag if the kernel doesn't
	 * support it.
	 *
	 * The function below returns EOPNOTSUPP it libbpf is too old to support
	 * setting the flags, but we just ignore that, since in such a case the
	 * best we can do is just attempt to run without the frags support.
	 */
	xdp_program__set_xdp_frags_support(xdp_prog, true);

	for (iface = opt->ifaces; iface; iface = iface->next) {
		if (find_prog(iface, false) != -ENOENT) {
			pr_warn("Already attached to %s, not reattaching\n",
				iface->ifname);
			continue;
		}

		ret = xdp_program__attach(xdp_prog, iface->ifindex, opt->xdp_mode, 0);
		if (ret) {
			pr_warn("Failed to attach XDP program to iface %s: %s\n",
				iface->ifname, strerror(-ret));
			goto end_detach;
		}

		ret = init_tx_port(init_prog, iface->ifindex);
		if (ret) {
			pr_warn("Failed to initiate TX port: %s\n",
				strerror(errno));
			goto end_detach;
		}

		pr_info("Loaded on interface %s\n", iface->ifname);
	}

end_destroy:
	xdp_forward__destroy(skel);
end:
	return ret;

end_detach:
	for (iface = opt->ifaces; iface; iface = iface->next)
		xdp_program__detach(xdp_prog, iface->ifindex, opt->xdp_mode, 0);
	goto end_destroy;
}

struct unload_opts {
	struct iface *ifaces;
} defaults_unload = {};

struct prog_option unload_options[] = {
	DEFINE_OPTION("devs", OPT_IFNAME_MULTI, struct unload_opts, ifaces,
		      .positional = true,
		      .metavar = "<ifname...>",
		      .min_num = 1,
		      .max_num = MAX_IFACE_NUM,
		      .help = "Redirect from and to devices <ifname...>"),
	END_OPTIONS
};


static int do_unload(const void *cfg, __unused const char *pin_root_path)
{
	const struct unload_opts *opt = cfg;
	int ret = EXIT_SUCCESS;
	struct iface *iface;

	for (iface = opt->ifaces; iface; iface = iface->next) {
		if (find_prog(iface, true)) {
			pr_warn("Couldn't find program on interface %s\n",
				iface->ifname);
			ret = EXIT_FAILURE;
		}
		pr_info("Unloaded from interface %s\n", iface->ifname);
	}

	return ret;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load XDP forwarding plane"),
	DEFINE_COMMAND(unload, "Unload XDP forwarding plane"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct load_opts load;
	struct unload_opts unload;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
