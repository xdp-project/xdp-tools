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
		"       xsk-drop       - AF_XDP socket-based drop\n"
		"       xsk-tx         - AF_XDP socket-based hairpin forwarding\n"
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

struct enum_val devmap_egress_actions[] = {
       {"forward", DEVMAP_EGRESS_FORWARD },
       {"drop", DEVMAP_EGRESS_DROP },
       {NULL, 0}
};

struct enum_val xsk_program_modes[] = {
       {"rxdrop", XSK_RXDROP},
       {"swap-macs", XSK_SWAP_MACS},
       {NULL, 0}
};

struct enum_val xsk_copy_modes[] = {
       {"auto", XSK_COPY_AUTO},
       {"copy", XSK_COPY_COPY},
       {"zero-copy", XSK_COPY_ZEROCOPY},
       {NULL, 0}
};

struct enum_val xsk_clocks[] = {
       {"MONOTONIC", XSK_CLOCK_MONOTONIC},
       {"REALTIME", XSK_CLOCK_REALTIME},
       {"TAI", XSK_CLOCK_TAI},
       {"BOOTTIME", XSK_CLOCK_BOOTTIME},
       {NULL, 0}
};

struct enum_val xsk_sched_policies[] = {
       {"SCHED_OTHER", XSK_SCHED_OTHER},
       {"SCHED_FIFO", XSK_SCHED_FIFO},
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
		      .help = "How to load (and store) data; default dpa"),
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
	DEFINE_OPTION("load-mode", OPT_ENUM, struct redirect_opts, load_mode,
		      .short_opt = 'l',
                      .metavar = "<mode>",
                      .typearg = basic_load_modes,
		      .help = "How to load (and store) data; default dpa"),
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
	DEFINE_OPTION("extended", OPT_BOOL, struct cpumap_opts, extended,
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
	DEFINE_OPTION("egress-action", OPT_ENUM, struct devmap_opts, egress_action,
		      .short_opt = 'A',
		      .typearg = devmap_egress_actions,
		      .metavar = "<action>",
		      .help = "Egress program <action>. Default is forward"),
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
	DEFINE_OPTION("egress-action", OPT_ENUM, struct devmap_multi_opts, egress_action,
		      .short_opt = 'A',
		      .typearg = devmap_egress_actions,
		      .metavar = "<action>",
		      .help = "Egress program <action>. Default is forward"),
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

struct prog_option xsk_options[] = {
	DEFINE_OPTION("queue", OPT_U32, struct xsk_opts, queue_idx,
		      .short_opt = 'q',
		      .metavar = "<queue>",
		      .help = "Queue index to use (default 0)"),
	DEFINE_OPTION("interval", OPT_U32, struct xsk_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Statistics update interval (default 2)"),
	DEFINE_OPTION("retries", OPT_U32, struct xsk_opts, retries,
		      .short_opt = 'O',
		      .metavar = "<number>",
		      .help = "Number of time-out retries per 1s interval (default 3)"),
	DEFINE_OPTION("frame-size", OPT_U32, struct xsk_opts, frame_size,
		      .short_opt = 'f',
		      .metavar = "<size>",
		      .help = "Data frame size (must be a power of two in aligned mode); (default 4096)"),
	DEFINE_OPTION("duration", OPT_U32, struct xsk_opts, duration,
		      .short_opt = 'd',
		      .metavar = "<seconds>",
		      .help = "Duration to run; default 0 (forever)"),
	DEFINE_OPTION("batch-size", OPT_U32, struct xsk_opts, batch_size,
		      .short_opt = 'b',
		      .metavar = "<packets>",
		      .help = "Batch size for receive loop; default 64"),
	DEFINE_OPTION("irq-string", OPT_STRING, struct xsk_opts, irq_string,
		      .short_opt = 'I',
		      .metavar = "<irq-string>",
		      .help = "Display driver interrupt statistics for interface associated with <irq-string>"),
	DEFINE_OPTION("poll", OPT_BOOL, struct xsk_opts, use_poll,
		      .short_opt = 'p',
		      .help = "Use poll syscall"),
	DEFINE_OPTION("no-need-wakeup", OPT_BOOL, struct xsk_opts, no_need_wakeup,
		      .short_opt = 'm',
		      .help = "Turn off use of driver need wakeup flag"),
	DEFINE_OPTION("unaligned", OPT_BOOL, struct xsk_opts, unaligned,
		      .short_opt = 'u',
		      .help = "Enable unaligned chunk placement"),
	DEFINE_OPTION("shared-umem", OPT_BOOL, struct xsk_opts, shared_umem,
		      .short_opt = 'M',
		      .help = "Enable XDP_SHARED_UMEM across multiple sockets"),
	DEFINE_OPTION("extra-stats", OPT_BOOL, struct xsk_opts, extra_stats,
		      .short_opt = 'x',
		      .help = "Display extra statistics"),
	DEFINE_OPTION("quiet", OPT_BOOL, struct xsk_opts, quiet,
		      .short_opt = 'Q',
		      .help = "Do not display any stats"),
	DEFINE_OPTION("app-stats", OPT_BOOL, struct xsk_opts, app_stats,
		      .short_opt = 'a',
		      .help = "Display application (syscall) statistics"),
	DEFINE_OPTION("busy-poll", OPT_BOOL, struct xsk_opts, busy_poll,
		      .short_opt = 'B',
		      .help = "Enable busy polling"),
	DEFINE_OPTION("frags", OPT_BOOL, struct xsk_opts, frags,
		      .short_opt = 'F',
		      .help = "Enable frags (multi-buffer) support"),
	DEFINE_OPTION("copy_mode", OPT_ENUM, struct xsk_opts, copy_mode,
		      .short_opt = 'C',
		      .typearg = xsk_copy_modes,
		      .metavar = "<mode>",
		      .help = "Use <mode> for copying data packets to userspace; default auto"),
	DEFINE_OPTION("clock", OPT_ENUM, struct xsk_opts, clock,
		      .short_opt = 'w',
		      .typearg = xsk_clocks,
		      .metavar = "<clock>",
		      .help = "Clock name to use; default MONOTONIC"),
	DEFINE_OPTION("policy", OPT_ENUM, struct xsk_opts, sched_policy,
		      .short_opt = 'W',
		      .typearg = xsk_sched_policies,
		      .metavar = "<policy>",
		      .help = "Scheduler policy; default SCHED_OTHER"),
	DEFINE_OPTION("schpri", OPT_U32, struct xsk_opts, sched_prio,
		      .short_opt = 'U',
		      .metavar = "<priority>",
		      .help = "Scheduler priority; default 0"),
	DEFINE_OPTION("attach-mode", OPT_ENUM, struct xsk_opts, attach_mode,
		      .short_opt = 'A',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct xsk_opts, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
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
	{ .name = "xsk-drop",
	  .func = do_xsk_drop,
	  .options = xsk_options,
	  .default_cfg = &defaults_xsk,
	  .doc = "AF_XDP-based packet drop" },
	{ .name = "xsk-tx",
	  .func = do_xsk_tx,
	  .options = xsk_options,
	  .default_cfg = &defaults_xsk,
	  .doc = "AF_XDP-based transmit back out an interface (hairpin forwarding)" },
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct basic_opts basic;
	struct cpumap_opts cpumap;
	struct devmap_opts devmap;
	struct devmap_multi_opts devmap_multi;
	struct xsk_opts xsk;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
