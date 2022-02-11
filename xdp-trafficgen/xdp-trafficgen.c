/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xdp_stats_kern_user.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>

#include "params.h"
#include "logging.h"
#include "util.h"
#include "stats.h"
#include "xdp-trafficgen.h"

#define PROG_NAME "xdp-trafficgen"

#ifndef BPF_F_TEST_XDP_LIVE_FRAMES
#define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
#endif

static bool status_exited = false;
static bool runners_exited = false;

void handle_signal(__unused int signal)
{
	status_exited = true;
}

static int run_status(struct bpf_map *stats_map, __u16 interval)
{
	int ret;
	signal(SIGINT, &handle_signal);

	ret = stats_poll(bpf_map__fd(stats_map), interval, &runners_exited, NULL, NULL);
	if (ret)
		pr_warn("Status poll failed: %s\n", strerror(-ret));
	status_exited = true;

	return ret;
}

struct udp_packet {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct udphdr udp;
	__u8 payload[64 - sizeof(struct udphdr)
		     - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __attribute__((__packed__));

static struct udp_packet pkt_udp = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.iph.version = 6,
	.iph.nexthdr = IPPROTO_UDP,
	.iph.payload_len = bpf_htons(sizeof(struct udp_packet)
				     - offsetof(struct udp_packet, udp)),
	.iph.hop_limit = 1,
	.iph.saddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(1)},
	.iph.daddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(2)},
	.udp.source = bpf_htons(1),
	.udp.dest = bpf_htons(1),
	.udp.len = bpf_htons(sizeof(struct udp_packet)
			     - offsetof(struct udp_packet, udp)),
};

struct thread_config {
	void *pkt;
	size_t pkt_size;
	__u32 cpu_core_id;
	__u32 num_pkts;
	__u32 batch_size;
	struct xdp_program *prog;
};

static int run_prog(const struct thread_config *cfg, bool *status_var)
{
#ifdef HAVE_LIBBPF_BPF_PROG_TEST_RUN_OPTS
	struct xdp_md ctx_in = {
		.data_end = cfg->pkt_size,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = cfg->pkt,
			    .data_size_in = cfg->pkt_size,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = cfg->num_pkts ?: 1 << 20,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
			    .batch_size = cfg->batch_size,
		);
	__u64 iterations = 0;
	cpu_set_t cpu_cores;
	int err;

	CPU_ZERO(&cpu_cores);
	CPU_SET(cfg->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	do {
		err = xdp_program__test_run(cfg->prog, &opts, 0);
		if (err)
			return -errno;
		iterations += opts.repeat;
	} while (!*status_var && (!cfg->num_pkts || cfg->num_pkts > iterations));

	return 0;
#else
	__unused const void *c = cfg, *s = status_var;
	return -EOPNOTSUPP;
#endif
}

static void *run_traffic(void *arg)
{
	const struct thread_config *cfg = arg;
	int err;

	err = run_prog(cfg, &status_exited);
	if (err)
		pr_warn("Couldn't run trafficgen program: %s\n", strerror(-err));

	runners_exited = true;
	return NULL;
}

static int probe_kernel_support(void)
{
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
			    .find_filename = "xdp-trafficgen.kern.o",
			    .prog_name = "xdp_drop");
	struct xdp_program *prog;
	int data = 0, err;
	bool status = 0;

	prog = xdp_program__create(&opts);
	if (!prog) {
		err = -errno;
		pr_warn("Couldn't load XDP program: %s\n", strerror(-err));
		return err;
	}

	const struct thread_config cfg = {
		.pkt = &data,
		.pkt_size = sizeof(data),
		.num_pkts = 1,
		.batch_size = 1,
		.prog = prog
	};
	err = run_prog(&cfg, &status);
	if (err == -EOPNOTSUPP)
		pr_warn("BPF_PROG_RUN with batch size support is missing from libbpf.\n");
	else if (err == -EINVAL)
		pr_warn("Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
	else if (err)
		pr_warn("Error probing kernel support: %s\n", strerror(-err));

	xdp_program__close(prog);
	return err;
}

static int create_runners(pthread_t **runner_threads, struct thread_config **thread_configs, int num_threads,
			  struct thread_config *tcfg, struct xdp_program *prog)
{
	struct thread_config *t;
	pthread_t *threads;
	int i, err;

	threads = calloc(sizeof(pthread_t), num_threads);
	if (!threads) {
		pr_warn("Couldn't allocate memory\n");
		return -ENOMEM;
	}

	t = calloc(sizeof(struct thread_config), num_threads);
	if (!t) {
		pr_warn("Couldn't allocate memory\n");
		free(threads);
		return -ENOMEM;
	}

	for (i = 0; i < num_threads; i++) {
		memcpy(&t[i], tcfg, sizeof(*tcfg));
		tcfg->cpu_core_id++;

		t[i].prog = xdp_program__clone(prog, 0);
		err = libxdp_get_error(t[i].prog);
		if (err) {
			pr_warn("Failed to clone xdp_program: %s\n", strerror(-err));
			t[i].prog = NULL;
			goto err;
		}

		err = pthread_create(&threads[i], NULL, run_traffic, &t[i]);
		if (err < 0) {
			pr_warn("Failed to create traffic thread: %s\n", strerror(-err));
			goto err;
		}
	}

	*runner_threads = threads;
	*thread_configs = t;

	return 0;

err:
	for (i = 0; i < num_threads; i++) {
		pthread_cancel(threads[i]);
		xdp_program__close(t[i].prog);
	}
	free(t);
	free(threads);

	return err;
}


static __be16 calc_udp_cksum(const struct udp_packet *pkt)
{
	__u32 chksum = pkt->iph.nexthdr + bpf_ntohs(pkt->iph.payload_len);
	int i;

	for (i = 0; i < 8; i++) {
		chksum += bpf_ntohs(pkt->iph.saddr.s6_addr16[i]);
		chksum += bpf_ntohs(pkt->iph.daddr.s6_addr16[i]);
	}
	chksum += bpf_ntohs(pkt->udp.source);
	chksum += bpf_ntohs(pkt->udp.dest);
	chksum += bpf_ntohs(pkt->udp.len);

	while (chksum >> 16)
		chksum = (chksum & 0xFFFF) + (chksum >> 16);
	return bpf_htons(~chksum);
}

static int get_mac_addr(const char *ifname, struct mac_addr *mac_addr)
{
	struct ifreq ifr = {};
	int fd, r;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	r = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (r) {
		r = -errno;
		goto end;
	}

	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, sizeof(*mac_addr));

end:
	close(fd);
	return r;
}


static const struct udpopt {
	__u32 num_pkts;
	struct iface iface;
	struct mac_addr dst_mac;
	struct mac_addr src_mac;
	struct ip_addr dst_ip;
	struct ip_addr src_ip;
	__u16 dst_port;
	__u16 src_port;
	__u16 dyn_ports;
	__u16 threads;
	__u16 interval;
} defaults_udp = {
	.interval = 1000,
	.threads = 1,
};

static int prepare_udp_pkt(const struct udpopt *cfg)
{
	struct mac_addr src_mac = cfg->src_mac;
	int err;

	if (macaddr_is_null(&src_mac)) {
		err = get_mac_addr(cfg->iface.ifname, &src_mac);
		if (err)
			return err;
	}
	memcpy(pkt_udp.eth.h_source, &src_mac, sizeof(src_mac));
	if (!macaddr_is_null(&cfg->dst_mac))
		memcpy(pkt_udp.eth.h_dest, &cfg->dst_mac, sizeof(cfg->dst_mac));

	if (!ipaddr_is_null(&cfg->src_ip)) {
		if (cfg->src_ip.af != AF_INET6) {
			pr_warn("Only IPv6 is supported\n");
			return 1;
		}
		pkt_udp.iph.saddr = cfg->src_ip.addr.addr6;
	}

	if (!ipaddr_is_null(&cfg->dst_ip)) {
		if (cfg->dst_ip.af != AF_INET6) {
			pr_warn("Only IPv6 is supported\n");
			return 1;
		}
		pkt_udp.iph.daddr = cfg->dst_ip.addr.addr6;
	}

	if (cfg->src_port)
		pkt_udp.udp.source = bpf_htons(cfg->src_port);
	if (cfg->dst_port)
		pkt_udp.udp.dest = bpf_htons(cfg->dst_port);
	pkt_udp.udp.check = calc_udp_cksum(&pkt_udp);
	return 0;
}

static int set_bpf_config(struct bpf_object *obj,
			  struct trafficgen_config *config,
			  struct trafficgen_state *state)
{
	int err = -ENOENT, set_maps = 0;
	struct bpf_map *map;
	const void *initval;
	char buf[1024];
	size_t val_sz;

	bpf_object__for_each_map(map, obj) {
		if (!bpf_map__is_internal(map))
			continue;

		if (strstr(bpf_map__name(map), ".rodata")) {
			initval = bpf_map__initial_value(map, &val_sz);
			if (val_sz > sizeof(buf)) {
				pr_warn(".rodata too big!\n");
				err = -E2BIG;
				goto out;
			}

			memcpy(buf, initval, val_sz);
			memcpy(buf, config, sizeof(*config));
			err = bpf_map__set_initial_value(map, buf, val_sz);
			if (err) {
				pr_warn("Couldn't set program .rodata: %s\n",
					strerror(-err));
				goto out;
			}
			set_maps++;
		}

		if (strstr(bpf_map__name(map), ".bss")) {
			err = bpf_map__set_initial_value(map, state,
							 sizeof(*state));
			if (err) {
				pr_warn("Couldn't set program .bss: %s\n",
					strerror(-err));
				goto out;
			}
			set_maps++;
		}
	}

	if (set_maps < 2) {
		pr_warn("Couldn't find rodata and bss maps\n");
	} else {
		err = 0;
	}
out:
	return err;
}

static struct prog_option udp_options[] = {
	DEFINE_OPTION("dst-mac", OPT_MACADDR, struct udpopt, dst_mac,
		      .short_opt = 'm',
		      .metavar = "<mac addr>",
		      .help = "Destination MAC address of generated packets"),
	DEFINE_OPTION("src-mac", OPT_MACADDR, struct udpopt, src_mac,
		      .short_opt = 'M',
		      .metavar = "<mac addr>",
		      .help = "Source MAC address of generated packets"),
	DEFINE_OPTION("dst-addr", OPT_IPADDR, struct udpopt, dst_ip,
		      .short_opt = 'a',
		      .metavar = "<addr>",
		      .help = "Destination IP address of generated packets"),
	DEFINE_OPTION("src-addr", OPT_IPADDR, struct udpopt, src_ip,
		      .short_opt = 'A',
		      .metavar = "<addr>",
		      .help = "Source IP address of generated packets"),
	DEFINE_OPTION("dst-port", OPT_U16, struct udpopt, dst_port,
		      .short_opt = 'p',
		      .metavar = "<port>",
		      .help = "Destination port of generated packets"),
	DEFINE_OPTION("src-port", OPT_U16, struct udpopt, src_port,
		      .short_opt = 'P',
		      .metavar = "<port>",
		      .help = "Source port of generated packets"),
	DEFINE_OPTION("dyn-ports", OPT_U16, struct udpopt, dyn_ports,
		      .short_opt = 'd',
		      .metavar = "<num ports>",
		      .help = "Dynamically vary destination port over a range of <num ports>"),
	DEFINE_OPTION("num-packets", OPT_U32, struct udpopt, num_pkts,
		      .short_opt = 'n',
		      .metavar = "<port>",
		      .help = "Number of packets to send"),
	DEFINE_OPTION("threads", OPT_U16, struct udpopt, threads,
		      .short_opt = 't',
		      .metavar = "<threads>",
		      .help = "Number of simultaneous threads to transmit from"),
	DEFINE_OPTION("interval", OPT_U16, struct udpopt, interval,
		      .short_opt = 'I',
		      .metavar = "<s>",
		      .help = "Output statistics with this interval"),
	DEFINE_OPTION("interface", OPT_IFNAME, struct udpopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	END_OPTIONS
};

int do_udp(const void *opt, __unused const char *pin_root_path)
{
	const struct udpopt *cfg = opt;

	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
			    .find_filename = "xdp-trafficgen.kern.o");
	struct thread_config *t = NULL, tcfg = {
		.pkt = &pkt_udp,
		.pkt_size = sizeof(pkt_udp),
		.num_pkts = cfg->num_pkts,
	};
	struct trafficgen_config bpf_config = {
		.port_start = cfg->dst_port,
		.port_range = cfg->dyn_ports,
		.ifindex_out = cfg->iface.ifindex,
	};
	struct trafficgen_state bpf_state = {
		.next_port = cfg->dst_port,
	};
	pthread_t *runner_threads = NULL;
	struct xdp_program *prog = NULL;
	struct bpf_map *stats_map;
	struct bpf_object *obj;
	int err = 0, i;
	char buf[100];

	err = probe_kernel_support();
	if (err)
		return err;

	err = prepare_udp_pkt(cfg);
	if (err)
		goto out;

	if (cfg->dyn_ports)
		opts.prog_name = "xdp_redirect_update_port";
	else
		opts.prog_name = "xdp_redirect_notouch";

	prog = xdp_program__create(&opts);
	if (!prog) {
		err = -errno;
		libxdp_strerror(err, buf, sizeof(buf));
		pr_warn("Couldn't open BPF file: %s\n", buf);
		goto out;
	}

	obj = xdp_program__bpf_obj(prog);
	err = set_bpf_config(obj, &bpf_config, &bpf_state);
	if (err)
		goto out;

	stats_map = bpf_object__find_map_by_name(obj, textify(XDP_STATS_MAP_NAME));
	if (!stats_map) {
		pr_warn("Couldn't find stats map\n");
		err = -ENOENT;
		goto out;
	}
	/* don't pin the map */
	bpf_map__set_pin_path(stats_map, NULL);

	err = bpf_object__load(obj);
	if (err)
		goto out;

	err = create_runners(&runner_threads, &t, cfg->threads, &tcfg, prog);
	if (err)
		goto out;

	pr_info("Transmitting on %s (ifindex %d)\n",
	       cfg->iface.ifname, cfg->iface.ifindex);

	err = run_status(stats_map, cfg->interval);
	status_exited = true;

	for (i = 0; i < cfg->threads; i++) {
		pthread_join(runner_threads[i], NULL);
		xdp_program__close(t[i].prog);
	}

out:
	xdp_program__close(prog);
	free(runner_threads);
	free(t);
        return err;
}


static const struct probeopt {
} defaults_probe = {};

static struct prog_option probe_options[] = {};

int do_probe(__unused const void *cfg, __unused const char *pin_root_path)
{
	int err = probe_kernel_support();

	if (!err)
		pr_info("Kernel supports live packet mode for XDP BPF_PROG_RUN.\n");
	return err;
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-trafficgen COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       udp         - run in UDP mode\n"
		"       help        - show this help message\n"
		"\n"
		"Use 'xdp-trafficgen COMMAND --help' to see options for each command\n");
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(udp, "Run in UDP mode"),
	DEFINE_COMMAND(probe, "Probe kernel support"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct udpopt udp;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
