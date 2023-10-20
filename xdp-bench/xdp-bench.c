#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "xdp-bench.h"
#include "params.h"

#define PROG_NAME "xdp-bench"

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-bench COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       drop           - Drop all packets on an interface\n"
		"       pass           - Pass all packets to the network stack\n"
		"       tx             - Transmit packets back out on an interface (hairpin forwarding)\n"
		"       redirect       - XDP redirect using the bpf_redirect() helper\n"
		"       redirect-cpu   - XDP CPU redirect using BPF_MAP_TYPE_CPUMAP\n"
		"       redirect-map   - XDP redirect using BPF_MAP_TYPE_DEVMAP\n"
		"       redirect-multi - XDP multi-redirect using BPF_MAP_TYPE_DEVMAP and the BPF_F_BROADCAST flag\n"
		"       help           - show this help message\n"
		"\n"
		"Use 'xdp-bench COMMAND --help' to see options for each command\n");
	return -1;
}


struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {NULL, 0}
};

struct enum_val basic_program_modes[] = {
       {"no-touch", BASIC_NO_TOUCH},
       {"read-data", BASIC_READ_DATA},
       {"parse-ip", BASIC_PARSE_IPHDR},
       {"swap-macs", BASIC_SWAP_MACS},
       {NULL, 0}
};

struct enum_val basic_load_modes[] = {
       {"dpa", BASIC_LOAD_DPA},
       {"load-bytes", BASIC_LOAD_BYTES},
       {NULL, 0}
};

struct enum_val cpumap_remote_actions[] = {
       {"disabled", ACTION_DISABLED},
       {"drop", ACTION_DROP},
       {"pass", ACTION_PASS},
       {"redirect", ACTION_REDIRECT},
       {NULL, 0}
};

struct enum_val cpumap_program_modes[] = {
       {"no-touch", CPUMAP_NO_TOUCH},
       {"touch", CPUMAP_TOUCH_DATA},
       {"round-robin", CPUMAP_CPU_ROUND_ROBIN},
       {"l4-proto", CPUMAP_CPU_L4_PROTO},
       {"l4-filter", CPUMAP_CPU_L4_PROTO_FILTER},
       {"l4-hash", CPUMAP_CPU_L4_HASH},
       {"l4-sport", CPUMAP_CPU_L4_SPORT},
       {"l4-dport", CPUMAP_CPU_L4_DPORT},
       {NULL, 0}
};


struct prog_option basic_options[] = {
	DEFINE_OPTION("packet-operation", OPT_ENUM, struct basic_opts, program_mode,
		      .short_opt = 'p',
		      .metavar = "<action>",
		      .typearg = basic_program_modes,
		      .help = "Action to take before dropping packet."),
	DEFINE_OPTION("program-mode", OPT_ENUM, struct basic_opts, program_mode,
		      .typearg = basic_program_modes,
		      .hidden = true),
	DEFINE_OPTION("load-mode", OPT_ENUM, struct basic_opts, load_mode,
		      .short_opt = 'l',
                      .metavar = "<mode>",
                      .typearg = basic_load_modes,
		      .help = "How to load data when parsing IP header (with -p parse-ip; default dpa)"),
	DEFINE_OPTION("rxq-stats", OPT_BOOL, struct basic_opts, rxq_stats,
		      .short_opt = 'r',
		      .help = "Collect per-RXQ drop statistics"),
	DEFINE_OPTION("interval", OPT_U32, struct basic_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Polling interval (default 2)"),
	DEFINE_OPTION("extended", OPT_BOOL, struct basic_opts, extended,
		      .short_opt = 'e',
		      .help = "Start running in extended output mode (C^\\ to toggle)"),
	DEFINE_OPTION("xdp-mode", OPT_ENUM, struct basic_opts, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct basic_opts, iface_in,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	END_OPTIONS
};

struct prog_option redirect_basic_options[] = {
	DEFINE_OPTION("interval", OPT_U32, struct redirect_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Polling interval (default 2)"),
	DEFINE_OPTION("stats", OPT_BOOL, struct redirect_opts, stats,
		      .short_opt = 's',
		      .help = "Enable statistics for transmitted packets (not just errors)"),
	DEFINE_OPTION("extended", OPT_BOOL, struct redirect_opts, extended,
		      .short_opt = 'e',
		      .help = "Start running in extended output mode (C^\\ to toggle)"),
	DEFINE_OPTION("mode", OPT_ENUM, struct redirect_opts, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev_in", OPT_IFNAME, struct redirect_opts, iface_in,
		      .positional = true,
		      .metavar = "<ifname_in>",
		      .required = true,
		      .help = "Redirect from device <ifname>"),
	DEFINE_OPTION("dev_out", OPT_IFNAME, struct redirect_opts, iface_out,
		      .positional = true,
		      .metavar = "<ifname_out>",
		      .required = true,
		      .help = "Redirect to device <ifname>"),
	END_OPTIONS
};

struct prog_option redirect_cpumap_options[] = {
	DEFINE_OPTION("cpu", OPT_U32_MULTI, struct cpumap_opts, cpus,
		      .short_opt = 'c',
		      .metavar = "<cpu>",
		      .required = true,
		      .help = "Insert CPU <cpu> into CPUMAP (can be specified multiple times)"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct cpumap_opts, iface_in,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Run on <ifname>"),
	DEFINE_OPTION("program-mode", OPT_ENUM, struct cpumap_opts, program_mode,
		      .short_opt = 'p',
		      .metavar = "<mode>",
		      .typearg = cpumap_program_modes,
		      .help = "Redirect to CPUs using <mode>. Default l4-hash."),
	DEFINE_OPTION("remote-action", OPT_ENUM, struct cpumap_opts, remote_action,
		      .short_opt = 'r',
		      .metavar = "<action>",
		      .typearg = cpumap_remote_actions,
		      .help = "Perform <action> on the remote CPU. Default disabled."),
	DEFINE_OPTION("redirect-device", OPT_IFNAME, struct cpumap_opts, redir_iface,
		      .short_opt = 'D',
		      .metavar = "<ifname>",
		      .help = "Redirect packets to <ifname> on remote CPU (when --remote-action is 'redirect')"),
	DEFINE_OPTION("qsize", OPT_U32, struct cpumap_opts, qsize,
		      .short_opt = 'q',
		      .metavar = "<packets>",
		      .help = "CPUMAP queue size (default 2048)"),
	DEFINE_OPTION("stress-mode", OPT_BOOL, struct cpumap_opts, stress_mode,
		      .short_opt = 'x',
		      .help = "Stress the kernel CPUMAP setup and teardown code while running"),
	DEFINE_OPTION("interval", OPT_U32, struct cpumap_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Polling interval (default 2)"),
	DEFINE_OPTION("stats", OPT_BOOL, struct cpumap_opts, stats,
		      .short_opt = 's',
		      .help = "Enable statistics for transmitted packets (not just errors)"),
	DEFINE_OPTION("extended", OPT_BOOL, struct basic_opts, extended,
		      .short_opt = 'e',
		      .help = "Start running in extended output mode (C^\\ to toggle)"),
	DEFINE_OPTION("xdp-mode", OPT_ENUM, struct cpumap_opts, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	END_OPTIONS
};

struct prog_option redirect_devmap_options[] = {
	DEFINE_OPTION("load-egress", OPT_BOOL, struct devmap_opts, load_egress,
		      .short_opt = 'X',
		      .help = "Load an egress program into the devmap"),
	DEFINE_OPTION("interval", OPT_U32, struct devmap_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Polling interval (default 2)"),
	DEFINE_OPTION("stats", OPT_BOOL, struct devmap_opts, stats,
		      .short_opt = 's',
		      .help = "Enable statistics for transmitted packets (not just errors)"),
	DEFINE_OPTION("extended", OPT_BOOL, struct devmap_opts, extended,
		      .short_opt = 'e',
		      .help = "Start running in extended output mode (C^\\ to toggle)"),
	DEFINE_OPTION("mode", OPT_ENUM, struct devmap_opts, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev_in", OPT_IFNAME, struct devmap_opts, iface_in,
		      .positional = true,
		      .metavar = "<ifname_in>",
		      .required = true,
		      .help = "Redirect from device <ifname>"),
	DEFINE_OPTION("dev_out", OPT_IFNAME, struct devmap_opts, iface_out,
		      .positional = true,
		      .metavar = "<ifname_out>",
		      .required = true,
		      .help = "Redirect to device <ifname>"),
	END_OPTIONS
};

struct prog_option redirect_devmap_multi_options[] = {
	DEFINE_OPTION("load-egress", OPT_BOOL, struct devmap_multi_opts, load_egress,
		      .short_opt = 'X',
		      .help = "Load an egress program into the devmap"),
	DEFINE_OPTION("interval", OPT_U32, struct devmap_multi_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Polling interval (default 2)"),
	DEFINE_OPTION("stats", OPT_BOOL, struct devmap_multi_opts, stats,
		      .short_opt = 's',
		      .help = "Enable statistics for transmitted packets (not just errors)"),
	DEFINE_OPTION("extended", OPT_BOOL, struct devmap_multi_opts, extended,
		      .short_opt = 'e',
		      .help = "Start running in extended output mode (C^\\ to toggle)"),
	DEFINE_OPTION("mode", OPT_ENUM, struct devmap_multi_opts, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("devs", OPT_IFNAME_MULTI, struct devmap_multi_opts, ifaces,
		      .positional = true,
		      .metavar = "<ifname...>",
		      .min_num = 2,
		      .max_num = MAX_IFACE_NUM,
		      .required = true,
		      .help = "Redirect from and to devices <ifname...>"),
	END_OPTIONS
};

static const struct prog_command cmds[] = {
	{ .name = "drop",
	  .func = do_drop,
	  .options = basic_options,
	  .default_cfg = &defaults_drop,
	  .doc = "Drop all packets on an interface" },
	{ .name = "pass",
	  .func = do_pass,
	  .options = basic_options,
	  .default_cfg = &defaults_pass,
	  .doc = "Pass all packets to the network stack" },
	{ .name = "tx",
	  .func = do_tx,
	  .options = basic_options,
	  .default_cfg = &defaults_tx,
	  .doc = "Transmit packets back out an interface (hairpin forwarding)" },
	DEFINE_COMMAND_NAME("redirect", redirect_basic,
			    "XDP redirect using the bpf_redirect() helper"),
	DEFINE_COMMAND_NAME("redirect-cpu", redirect_cpumap,
			    "XDP CPU redirect using BPF_MAP_TYPE_CPUMAP"),
	DEFINE_COMMAND_NAME("redirect-map", redirect_devmap,
			    "XDP redirect using BPF_MAP_TYPE_DEVMAP"),
	DEFINE_COMMAND_NAME(
		"redirect-multi", redirect_devmap_multi,
		"XDP multi-redirect using BPF_MAP_TYPE_DEVMAP and the BPF_F_BROADCAST flag"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct basic_opts basic;
	struct cpumap_opts cpumap;
	struct devmap_opts devmap;
	struct devmap_multi_opts devmap_multi;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
