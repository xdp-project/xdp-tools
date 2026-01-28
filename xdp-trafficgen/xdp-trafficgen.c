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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xdp_stats_kern_user.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netdev.h>

#include "params.h"
#include "logging.h"
#include "util.h"
#include "xdp_sample.h"
#include "xdp-trafficgen.h"
#include "xdpsock.h"

#include "xdp_trafficgen.skel.h"

#define PROG_NAME "xdp-trafficgen"

#ifndef BPF_F_TEST_XDP_LIVE_FRAMES
#define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
#endif

#define IFINDEX_LO 1

static int mask = SAMPLE_DEVMAP_XMIT_CNT_MULTI | SAMPLE_DROP_OK;

DEFINE_SAMPLE_INIT(xdp_trafficgen);

static bool status_exited = false;

struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {NULL, 0}
};

static const char *driver_pass_list[] = {
	"bnxt",
	"ena",
	"gve",
	"i40e",
	"ice",
	"igb",
	"igc",
	"ixgbe",
	"octeontx2",
	"stmmac",
	"mlx5_core",
};

static bool driver_needs_xdp_pass(const struct iface *iface)
{
	const char *name = get_driver_name(iface->ifindex);
	struct xdp_multiprog *mp;
	__u64 feature_flags;
	size_t i;
	int err;

	/* If the interface already has the NDO_XMIT feature, we don't need to load anything */
	err = iface_get_xdp_feature_flags(iface->ifindex, &feature_flags);
	if (!err && feature_flags & NETDEV_XDP_ACT_NDO_XMIT)
		return false;

	mp = xdp_multiprog__get_from_ifindex(iface->ifindex);
	if (!IS_ERR_OR_NULL(mp)) {
		pr_debug("Interface %s already has an XDP program loaded\n", iface->ifname);
		xdp_multiprog__close(mp);
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(driver_pass_list); i++) {
		if (!strcmp(name, driver_pass_list[i])) {
			pr_debug("Driver %s on interface %s needs an xdp_pass program to use XDP_REDIRECT\n",
				 name, iface->ifname);
			return true;
		}
	}

	return false;
}

static int check_iface_support(const struct iface *iface)
{
	__u64 feature_flags = 0;
	int err;

	err = iface_get_xdp_feature_flags(iface->ifindex, &feature_flags);
	if (err || !feature_flags) {
		/* The libbpf query function, doesn't distinguish between
		 * "querying is not supported" and "no feature flags are set",
		 * so treat a 0-value feature_flags as a failure to query
		 * instead of refuring to run because the NDO_XMIT bit is not
		 * set.
		 */
		pr_warn("Couldn't query XDP features for interface %s (%d).\n"
			"Continuing anyway, but running may fail!\n",
			iface->ifname, -err);
	} else if (!(feature_flags & NETDEV_XDP_ACT_NDO_XMIT)) {
		pr_warn("Interface %s does not support sending packets via XDP.\n",
			iface->ifname);
		return -EOPNOTSUPP;
	}

	return 0;
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

	kill(getpid(), SIGINT);
	return NULL;
}

static int probe_kernel_support(void)
{
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts);
	struct xdp_trafficgen *skel;
	struct xdp_program *prog;
	__u8 data[ETH_HLEN] = {};
	bool status = 0;
	int err;

	skel = xdp_trafficgen__open();
	if (!skel) {
		err = -errno;
		pr_warn("Couldn't open XDP program: %s\n", strerror(-err));
		return err;
	}

	err = sample_init_pre_load(skel, "lo");
	if (err < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-err));
		goto out;
	}

	opts.obj = skel->obj;
	opts.prog_name = "xdp_drop";

	prog = xdp_program__create(&opts);
	if (!prog) {
		err = -errno;
		pr_warn("Couldn't load XDP program: %s\n", strerror(-err));
		goto out;
	}

	const struct thread_config cfg = {
		.pkt = data,
		.pkt_size = sizeof(data),
		.num_pkts = 1,
		.batch_size = 1,
		.prog = prog
	};
	err = run_prog(&cfg, &status);
	if (err == -EOPNOTSUPP) {
		pr_warn("BPF_PROG_RUN with batch size support is missing from libbpf.\n");
	}  else if (err == -EINVAL) {
		err = -EOPNOTSUPP;
		pr_warn("Kernel doesn't support live packet mode for XDP BPF_PROG_RUN.\n");
	} else if (err) {
		pr_warn("Error probing kernel support: %s\n", strerror(-err));
	}

	xdp_program__close(prog);
out:
	xdp_trafficgen__destroy(skel);
	return err;
}

static int create_runners(pthread_t **runner_threads, struct thread_config **thread_configs, int num_threads,
			  struct thread_config *tcfg, struct xdp_program *prog)
{
	struct thread_config *t;
	pthread_t *threads;
	int i, err;

	threads = calloc(num_threads, sizeof(pthread_t));
	if (!threads) {
		pr_warn("Couldn't allocate memory\n");
		return -ENOMEM;
	}

	t = calloc(num_threads, sizeof(struct thread_config));
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
	__u16 pkt_size;
	__u8 hop_limit;
} defaults_udp = {
	.interval = 1,
	.threads = 1,
	.pkt_size = 64,
	.hop_limit = 1,
};

static struct udp_packet *prepare_udp_pkt(const struct udpopt *cfg)
{
	struct mac_addr src_mac = cfg->src_mac;
	struct udp_packet *pkt = NULL;
	__u16 payload_len;
	int err;

	if (macaddr_is_null(&src_mac)) {
		err = get_mac_addr(cfg->iface.ifindex, &src_mac);
		if (err)
			goto err;
	}

	if (cfg->pkt_size < sizeof(*pkt)) {
		pr_warn("Minimum packet size is %zu bytes\n", sizeof(*pkt));
		goto err;
	}


	pkt = calloc(1, cfg->pkt_size);
	if (!pkt)
		goto err;

	memcpy(pkt, &pkt_udp, sizeof(*pkt));

	payload_len = cfg->pkt_size - offsetof(struct udp_packet, udp);
	pkt->iph.payload_len = bpf_htons(payload_len);
	pkt->iph.hop_limit = cfg->hop_limit;
	pkt->udp.len = bpf_htons(payload_len);

	memcpy(pkt->eth.h_source, &src_mac, sizeof(src_mac));
	if (!macaddr_is_null(&cfg->dst_mac))
		memcpy(pkt->eth.h_dest, &cfg->dst_mac, sizeof(cfg->dst_mac));

	if (!ipaddr_is_null(&cfg->src_ip)) {
		if (cfg->src_ip.af != AF_INET6) {
			pr_warn("Only IPv6 is supported\n");
			goto err;
		}
		pkt->iph.saddr = cfg->src_ip.addr.addr6;
	}

	if (!ipaddr_is_null(&cfg->dst_ip)) {
		if (cfg->dst_ip.af != AF_INET6) {
			pr_warn("Only IPv6 is supported\n");
			goto err;
		}
		pkt->iph.daddr = cfg->dst_ip.addr.addr6;
	}

	if (cfg->src_port)
		pkt->udp.source = bpf_htons(cfg->src_port);
	if (cfg->dst_port)
		pkt->udp.dest = bpf_htons(cfg->dst_port);
	pkt->udp.check = calc_udp_cksum(pkt);

	return pkt;

err:
	free(pkt);
	return NULL;
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
	DEFINE_OPTION("pkt-size", OPT_U16, struct udpopt, pkt_size,
		      .short_opt = 's',
		      .metavar = "<bytes>",
		      .help = "Packet size. Default 64."),
	DEFINE_OPTION("threads", OPT_U16, struct udpopt, threads,
		      .short_opt = 't',
		      .metavar = "<threads>",
		      .help = "Number of simultaneous threads to transmit from"),
	DEFINE_OPTION("interval", OPT_U16, struct udpopt, interval,
		      .short_opt = 'I',
		      .metavar = "<s>",
		      .help = "Output statistics with this interval"),
	DEFINE_OPTION("hop-limit", OPT_U8, struct udpopt, hop_limit,
		      .short_opt = 'l',
		      .metavar = "<hops>",
		      .help = "Hop limit to set in the IP header. Default 1."),
	DEFINE_OPTION("interface", OPT_IFNAME, struct udpopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
	END_OPTIONS
};

int do_udp(const void *opt, __unused const char *pin_root_path)
{
	struct xdp_program *prog = NULL, *pass_prog = NULL;
	const struct udpopt *cfg = opt;

	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts);
	struct thread_config *t = NULL, tcfg = {
		.pkt_size = cfg->pkt_size,
		.num_pkts = cfg->num_pkts,
	};
	struct trafficgen_state bpf_state = {};
	struct xdp_trafficgen *skel = NULL;
	struct udp_packet *payload = NULL;
	pthread_t *runner_threads = NULL;
	int err = 0, i;
	char buf[100];
	__u32 key = 0;

	err = probe_kernel_support();
	if (err)
		return err;

	payload = prepare_udp_pkt(cfg);
	if (!payload) {
		err = -ENOMEM;
		goto out;
	}
	tcfg.pkt = payload;

	skel = xdp_trafficgen__open();
	if (!skel) {
		err = -errno;
		pr_warn("Couldn't open XDP program: %s\n", strerror(-err));
		goto out;
	}

	err = sample_init_pre_load(skel, cfg->iface.ifname);
	if (err < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-err));
		goto out;
	}

	skel->rodata->config.port_start = cfg->dst_port;
	skel->rodata->config.port_range = cfg->dyn_ports;
	skel->rodata->config.ifindex_out = cfg->iface.ifindex;
	bpf_state.next_port = cfg->dst_port;

	if (cfg->dyn_ports)
		opts.prog_name = "xdp_redirect_update_port";
	else
		opts.prog_name = "xdp_redirect_notouch";
	opts.obj = skel->obj;

	prog = xdp_program__create(&opts);
	if (!prog) {
		err = -errno;
		libxdp_strerror(err, buf, sizeof(buf));
		pr_warn("Couldn't open BPF file: %s\n", buf);
		goto out;
	}

	if (driver_needs_xdp_pass(&cfg->iface)) {
		DECLARE_LIBXDP_OPTS(xdp_program_opts, pass_opts);
		pass_opts.prog_name = "xdp_pass";
		pass_opts.find_filename = "xdp-dispatcher.o";
		pass_prog = xdp_program__create(&pass_opts);
		if (!pass_prog) {
			err = -errno;
			pr_warn("Couldn't load xdp_pass program\n");
			goto out;
		}
	}

	err = xdp_trafficgen__load(skel);
	if (err)
		goto out;

	if (pass_prog) {
		err = xdp_program__attach(pass_prog, cfg->iface.ifindex,
					  XDP_MODE_NATIVE, 0);
		if (err) {
			pr_warn("Couldn't attach xdp_pass program\n");
			xdp_program__close(pass_prog);
			pass_prog = NULL;
			goto out;
		}
	}

	err = check_iface_support(&cfg->iface);
	if (err)
		goto out;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.state_map),
				  &key, &bpf_state, BPF_EXIST);
	if (err) {
		err = -errno;
		pr_warn("Couldn't set initial state map value: %s\n", strerror(-err));
		goto out;
	}

	err = sample_init(skel, mask, IFINDEX_LO, cfg->iface.ifindex);
	if (err < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-err));
		goto out;
	}

	err = create_runners(&runner_threads, &t, cfg->threads, &tcfg, prog);
	if (err)
		goto out;

	pr_info("Transmitting on %s (ifindex %d)\n",
	       cfg->iface.ifname, cfg->iface.ifindex);

	err = sample_run(cfg->interval, NULL, NULL);
	status_exited = true;

	for (i = 0; i < cfg->threads; i++) {
		pthread_join(runner_threads[i], NULL);
		xdp_program__close(t[i].prog);
	}

out:
	if (pass_prog) {
		xdp_program__detach(pass_prog, cfg->iface.ifindex,
				    XDP_MODE_NATIVE, 0);
		xdp_program__close(pass_prog);
	}
	xdp_program__close(prog);
	xdp_trafficgen__destroy(skel);
	free(runner_threads);
	free(payload);
	free(t);
        return err;
}

const struct xsk_opts defaults_xsk_udp = {
	.attach_mode = XDP_MODE_NATIVE,
	.interval = 1,
	.retries = 3,
	.frame_size = 4096,
	.batch_size = 64,
	.tx_pkt_size = 64,
	.sched_policy = XSK_SCHED_OTHER,
	.clock = XSK_CLOCK_MONOTONIC,
	.vlan_id = 1,
	.vlan_pri = 0,
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


struct prog_option xsk_udp_options[] = {
	DEFINE_OPTION("dst-mac", OPT_MACADDR, struct xsk_opts, dst_mac,
		      .short_opt = 'm', .metavar = "<mac addr>",
		      .help = "Destination MAC address of generated packets"),
	DEFINE_OPTION("src-mac", OPT_MACADDR, struct xsk_opts, src_mac,
		      .short_opt = 'M', .metavar = "<mac addr>",
		      .help = "Source MAC address of generated packets"),
	DEFINE_OPTION("timestamp", OPT_BOOL, struct xsk_opts, timestamp,
		      .short_opt = 'y',
		      .help = "Add timestamp to packets"),
	DEFINE_OPTION("vlan-tag", OPT_BOOL, struct xsk_opts, vlan_tag,
		      .short_opt = 'V',
		      .help = "Add vlan tag to packets"),
	DEFINE_OPTION("vlan-id", OPT_U16, struct xsk_opts, vlan_id,
		      .short_opt = 'J',
		      .metavar = "<id>",
		      .help = "VLAN ID to insert into VLAN tag (with -V). Default 1."),
	DEFINE_OPTION("vlan-pri", OPT_U16, struct xsk_opts, vlan_pri,
		      .short_opt = 'K',
		      .metavar = "<pri>",
		      .help = "VLAN PRI to insert into VLAN tag (with -V). Default 0"),
	DEFINE_OPTION("fill-pattern", OPT_U32, struct xsk_opts, pkt_fill_pattern,
		      .short_opt = 'P',
		      .metavar = "<pattern>", .hex = true,
		      .help = "Fill pattern (u32 hex value)"),
	DEFINE_OPTION("tx-cycle-time", OPT_U64, struct xsk_opts, tx_cycle_us,
		      .short_opt = 'T',
		      .metavar = "<us>",
		      .help = "TX cycle time (usec)."),


	DEFINE_OPTION("queue", OPT_U32, struct xsk_opts, queue_idx,
		      .short_opt = 'q',
		      .metavar = "<queue>",
		      .help = "Queue index to use (default 0)"),
	DEFINE_OPTION("interval", OPT_U32, struct xsk_opts, interval,
		      .short_opt = 'i',
		      .metavar = "<seconds>",
		      .help = "Statistics update interval (default 1)"),
	DEFINE_OPTION("retries", OPT_U32, struct xsk_opts, retries,
		      .short_opt = 'O',
		      .metavar = "<number>",
		      .help = "Number of time-out retries per 1s interval (default 3)"),
	DEFINE_OPTION("frame-size", OPT_U32, struct xsk_opts, frame_size,
		      .short_opt = 'f',
		      .metavar = "<size>",
		      .help = "Data frame size (must be a power of two in aligned mode); default 4096"),
	DEFINE_OPTION("pkt-size", OPT_U16, struct xsk_opts, tx_pkt_size,
		      .short_opt = 's',
		      .metavar = "<size>",
		      .help = "Packet size of transmitted packets; default 64"),
	DEFINE_OPTION("duration", OPT_U32, struct xsk_opts, duration,
		      .short_opt = 'd',
		      .metavar = "<seconds>",
		      .help = "Duration to run; default 0 (forever)"),
	DEFINE_OPTION("pkt-count", OPT_U32, struct xsk_opts, pkt_count,
		      .short_opt = 'c',
		      .metavar = "<number>",
		      .help = "Number of packets to send before exiting; default 0 (forever)"),
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
		      .help = "Turn off use of driver need wakeup flag"),
	DEFINE_OPTION("unaligned", OPT_BOOL, struct xsk_opts, unaligned,
		      .short_opt = 'u',
		      .help = "Enable unaligned chunk placement"),
	DEFINE_OPTION("shared-umem", OPT_BOOL, struct xsk_opts, shared_umem,
		      .help = "Enable XDP_SHARED_UMEM across multiple sockets"),
	DEFINE_OPTION("extra-stats", OPT_BOOL, struct xsk_opts, extra_stats,
		      .short_opt = 'x',
		      .help = "Display extra statistics"),
	DEFINE_OPTION("quiet", OPT_BOOL, struct xsk_opts, quiet,
		      .short_opt = 'Q',
		      .help = "Do not display any statistics"),
	DEFINE_OPTION("app-stats", OPT_BOOL, struct xsk_opts, app_stats,
		      .short_opt = 'a',
		      .help = "Display application (syscall) statistics"),
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

static int do_xsk_udp(const void *cfg, __unused const char *pin_root_path)
{
	const struct xsk_opts *opt = cfg;
	struct xsk_ctx *ctx;
	pthread_t pt;
	int ret;

	ret = xsk_validate_opts(opt);
	if (ret)
		return ret;

	ctx = xsk_ctx__create(opt, XSK_BENCH_TXONLY);
	ret = libxdp_get_error(ctx);
	if (ret)
		return ret;

	pr_info("Transmitting on %s (ifindex %d)\n",
	       opt->iface.ifname, opt->iface.ifindex);

	ret = xsk_start_bench(ctx, &pt);
	if (ret)
		goto out;

	ret = xsk_stats_poller(ctx);
	pthread_join(pt, NULL);

out:
	xsk_ctx__destroy(ctx);
	return ret;
}

struct tcp_packet {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct tcphdr tcp;
	__u8 payload[1500 - sizeof(struct tcphdr)
		     - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __attribute__((__packed__));

static __unused struct tcp_packet pkt_tcp = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.iph.version = 6,
	.iph.nexthdr = IPPROTO_TCP,
	.iph.payload_len = bpf_htons(sizeof(struct tcp_packet)
				     - offsetof(struct tcp_packet, tcp)),
	.iph.hop_limit = 64,
	.iph.saddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(1)},
	.iph.daddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(2)},
	.tcp.source = bpf_htons(1),
	.tcp.dest = bpf_htons(1),
	.tcp.window = bpf_htons(0x100),
	.tcp.doff = 5,
	.tcp.ack = 1,
};

static void hexdump_data(void *data, int size)
{
	unsigned char *ptr = data;
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			pr_debug("\n%06X: ", i);
		else if (i % 2 == 0)
			pr_debug(" ");
		pr_debug("%02X", *ptr++);
	}
	pr_debug("\n");
}

static __be16 calc_tcp_cksum(const struct tcp_packet *pkt)
{
	__u32 chksum = bpf_htons(pkt->iph.nexthdr) + pkt->iph.payload_len;
	int payload_len = sizeof(pkt->payload);
	struct tcphdr tcph_ = pkt->tcp;
	__u16 *ptr = (void *)&tcph_;
	int i;

	tcph_.check = 0;

	for (i = 0; i < 8; i++) {
		chksum += pkt->iph.saddr.s6_addr16[i];
		chksum += pkt->iph.daddr.s6_addr16[i];
	}
	for (i = 0; i < 10; i++)
		chksum += *(ptr++);

	ptr = (void *)&pkt->payload;
	for (i = 0; i < payload_len / 2; i++)
		chksum += *(ptr++);

	if (payload_len % 2)
		chksum += (*((__u8 *)ptr)) << 8;

	while (chksum >> 16)
		chksum = (chksum & 0xFFFF) + (chksum >> 16);

	return ~chksum;
}

static void prepare_tcp_pkt(const struct tcp_flowkey *fkey,
			    const struct tcp_flowstate *fstate)
{
	memcpy(pkt_tcp.eth.h_source, fstate->src_mac, ETH_ALEN);
	memcpy(pkt_tcp.eth.h_dest, fstate->dst_mac, ETH_ALEN);

	pkt_tcp.iph.saddr = fkey->src_ip;
	pkt_tcp.iph.daddr = fkey->dst_ip;
	pkt_tcp.tcp.source = fkey->src_port;
	pkt_tcp.tcp.dest = fkey->dst_port;
	pkt_tcp.tcp.seq = bpf_htonl(fstate->seq);
	pkt_tcp.tcp.ack_seq = bpf_htonl(fstate->rcv_seq);

	pkt_tcp.tcp.check = calc_tcp_cksum(&pkt_tcp);
	pr_debug("TCP packet:\n");
	hexdump_data(&pkt_tcp, sizeof(pkt_tcp));
}

static const struct tcpopt {
	__u32 num_pkts;
	struct iface iface;
	char *dst_addr;
	__u16 dst_port;
	__u16 interval;
	__u16 timeout;
	enum xdp_attach_mode mode;
} defaults_tcp = {
	.interval = 1,
	.dst_port = 10000,
	.timeout = 2,
	.mode = XDP_MODE_NATIVE,
};

static struct prog_option tcp_options[] = {
	DEFINE_OPTION("dst-port", OPT_U16, struct tcpopt, dst_port,
		      .short_opt = 'p',
		      .metavar = "<port>",
		      .help = "Connect to destination <port>. Default 10000"),
	DEFINE_OPTION("num-packets", OPT_U32, struct tcpopt, num_pkts,
		      .short_opt = 'n',
		      .metavar = "<port>",
		      .help = "Number of packets to send"),
	DEFINE_OPTION("interval", OPT_U16, struct tcpopt, interval,
		      .short_opt = 'I',
		      .metavar = "<s>",
		      .help = "Output statistics with this interval"),
	DEFINE_OPTION("timeout", OPT_U16, struct tcpopt, timeout,
		      .short_opt = 't',
		      .metavar = "<s>",
		      .help = "TCP connect timeout (default 2 seconds)."),
	DEFINE_OPTION("interface", OPT_IFNAME, struct tcpopt, iface,
		      .metavar = "<ifname>",
		      .required = true,
		      .short_opt = 'i',
		      .help = "Connect through device <ifname>"),
	DEFINE_OPTION("mode", OPT_ENUM, struct tcpopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load ingress XDP program in <mode>; default native"),
	DEFINE_OPTION("dst-addr", OPT_STRING, struct tcpopt, dst_addr,
		      .positional = true,
		      .required = true,
		      .metavar = "<hostname>",
		      .help = "Destination host of generated stream"),
	END_OPTIONS
};

int do_tcp(const void *opt, __unused const char *pin_root_path)
{
	const struct tcpopt *cfg = opt;

	struct addrinfo *ai = NULL, hints = {
		.ai_family = AF_INET6,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct ip_addr local_addr = { .af = AF_INET6 }, remote_addr = { .af = AF_INET6 };
	struct bpf_map *state_map = NULL, *fstate_map;
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts,
			    .prog_name = "xdp_handle_tcp_recv");
	struct xdp_program *ifindex_prog = NULL, *test_prog = NULL;
	struct sockaddr_in6 local_saddr = {}, *addr6;
	struct thread_config *t = NULL, tcfg = {
		.pkt = &pkt_tcp,
		.pkt_size = sizeof(pkt_tcp),
		.num_pkts = cfg->num_pkts,
	};
	struct trafficgen_state bpf_state = {};
	struct xdp_trafficgen *skel = NULL;
	char buf_local[50], buf_remote[50];
	pthread_t *runner_threads = NULL;
	socklen_t sockaddr_sz, tcpi_sz;
	__u16 local_port, remote_port;
	int sock = -1, err = -EINVAL;
	struct tcp_flowstate fstate;
	struct timeval timeout = {
		.tv_sec = cfg->timeout,
	};
	struct tcp_info tcpi = {};
	bool attached = false;
	__u16 num_threads = 1;
	__u32 key = 0;
	char port[6];
	int i, sopt;

	err = probe_kernel_support();
	if (err)
		return err;

	skel = xdp_trafficgen__open();
	if (!skel) {
		err = -errno;
		pr_warn("Couldn't open XDP program: %s\n", strerror(-err));
		goto out;
	}

	err = sample_init_pre_load(skel, cfg->iface.ifname);
	if (err < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-err));
		goto out;
	}

	opts.obj = skel->obj;
	skel->rodata->config.ifindex_out = cfg->iface.ifindex;

	snprintf(port, sizeof(port), "%d", cfg->dst_port);

	err = getaddrinfo(cfg->dst_addr, port, &hints, &ai);
	if (err) {
		pr_warn("Couldn't resolve hostname: %s\n", gai_strerror(err));
		goto out;
	}

	addr6 = (struct sockaddr_in6* )ai->ai_addr;
	remote_addr.addr.addr6 = addr6->sin6_addr;
	remote_port = bpf_ntohs(addr6->sin6_port);

	bpf_state.flow_key.dst_port = addr6->sin6_port;
	bpf_state.flow_key.dst_ip = addr6->sin6_addr;

	print_addr(buf_remote, sizeof(buf_remote), &remote_addr);

	ifindex_prog = xdp_program__create(&opts);
	if (!ifindex_prog) {
		err = -errno;
		pr_warn("Couldn't open XDP program: %s\n", strerror(-err));
		goto out;
	}

	opts.prog_name = "xdp_redirect_send_tcp";
	test_prog = xdp_program__create(&opts);
	if (!test_prog) {
		err = -errno;
		pr_warn("Couldn't find test program: %s\n", strerror(-err));
		goto out;
	}

	state_map = skel->maps.state_map;
	fstate_map = skel->maps.flow_state_map;

	if (!fstate_map) {
		pr_warn("Couldn't find BPF maps\n");
		goto out;
	}

	err = xdp_program__attach(ifindex_prog, cfg->iface.ifindex, cfg->mode, 0);
	if (err) {
		err = -errno;
		pr_warn("Couldn't attach XDP program to iface '%s': %s\n",
			cfg->iface.ifname, strerror(-err));
		goto out;
	}
	attached = true;

	err = check_iface_support(&cfg->iface);
	if (err)
		goto out;

	err = bpf_map_update_elem(bpf_map__fd(state_map),
				  &key, &bpf_state, BPF_EXIST);

	if (err) {
		err = -errno;
		pr_warn("Couldn't set initial state map value: %s\n", strerror(-err));
		goto out;
	}

	err = sample_init(skel, mask, IFINDEX_LO, cfg->iface.ifindex);
	if (err < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-err));
		goto out;
	}

	sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = -errno;
		pr_warn("Couldn't open TCP socket: %s\n", strerror(-err));
		goto out;
	}

	err = setsockopt(sock, SOL_SOCKET, SO_BINDTOIFINDEX,
			 &cfg->iface.ifindex, sizeof(cfg->iface.ifindex));
	if (err) {
		err = -errno;
		pr_warn("Couldn't bind to device '%s': %s\n", cfg->iface.ifname, strerror(-err));
		goto out;
	}

	sopt = fcntl(sock, F_GETFL, NULL);
	if (sopt < 0) {
		err = -errno;
		pr_warn("Couldn't get socket opts: %s\n", strerror(-err));
		goto out;
	}

	err = fcntl(sock, F_SETFL, sopt | O_NONBLOCK);
	if (err) {
		err = -errno;
		pr_warn("Couldn't set socket non-blocking: %s\n", strerror(-err));
		goto out;
	}

	err = connect(sock, ai->ai_addr, ai->ai_addrlen);
	if (err && errno == EINPROGRESS) {
		fd_set wait;

		FD_ZERO(&wait);
		FD_SET(sock, &wait);

		err = select(sock + 1, NULL, &wait, NULL, &timeout);
		if (!err) {
			err = -1;
			errno = ETIMEDOUT;
		} else if (err > 0) {
			err = 0;
		}
	}
	if (err) {
		err = -errno;
		pr_warn("Couldn't connect to destination: %s\n", strerror(-err));
		goto out;
	}

	err = fcntl(sock, F_SETFL, sopt);
	if (err) {
		err = -errno;
		pr_warn("Couldn't reset socket opts: %s\n", strerror(-err));
		goto out;
	}

	sockaddr_sz = sizeof(local_saddr);
	err = getsockname(sock, (struct sockaddr *)&local_saddr, &sockaddr_sz);
	if (err) {
		err = -errno;
		pr_warn("Couldn't get local address: %s\n", strerror(-err));
		goto out;
	}

	local_addr.addr.addr6 = local_saddr.sin6_addr;
	local_port = bpf_htons(local_saddr.sin6_port);
	print_addr(buf_local, sizeof(buf_local), &local_addr);

	printf("Connected to %s port %d from %s port %d\n",
	       buf_remote, remote_port, buf_local, local_port);

	bpf_state.flow_key.src_port = local_saddr.sin6_port;
	bpf_state.flow_key.src_ip = local_saddr.sin6_addr;

	tcpi_sz = sizeof(tcpi);
	err = getsockopt(sock, IPPROTO_TCP, TCP_INFO, &tcpi, &tcpi_sz);
	if (err) {
		err = -errno;
		pr_warn("Couldn't get TCP_INFO for socket: %s\n", strerror(-err));
		goto out;
	}

	err = bpf_map_lookup_elem(bpf_map__fd(fstate_map),
				  &bpf_state.flow_key, &fstate);
	if (err) {
		err = -errno;
		pr_warn("Couldn't find flow state in map: %s\n", strerror(-err));
		goto out;
	}

	if (tcpi.tcpi_snd_wnd != fstate.window) {
		pr_warn("TCP_INFO and packet data disagree on window (%u != %u)\n",
			tcpi.tcpi_snd_wnd, fstate.window);
	}

	fstate.wscale = tcpi.tcpi_rcv_wscale;
	fstate.flow_state = FLOW_STATE_RUNNING;
	err = bpf_map_update_elem(bpf_map__fd(fstate_map),
				  &bpf_state.flow_key, &fstate, BPF_EXIST);
	if (err) {
		err = -errno;
		pr_warn("Couldn't update flow state map: %s\n", strerror(-err));
		goto out;
	}

	err = bpf_map_update_elem(bpf_map__fd(state_map),
				  &key, &bpf_state, BPF_EXIST);
	if (err) {
		err = -errno;
		pr_warn("Couldn't update program state map: %s\n", strerror(-err));
		goto out;
	}

	prepare_tcp_pkt(&bpf_state.flow_key, &fstate);

	err = create_runners(&runner_threads, &t, num_threads, &tcfg, test_prog);
	if (err)
		goto out;

	err = sample_run(cfg->interval, NULL, NULL);
	status_exited = true;
	for (i = 0; i < num_threads; i++) {
		pthread_join(runner_threads[i], NULL);
		xdp_program__close(t[i].prog);
	}

	/* send 3 RSTs with 200ms interval to kill the other side of the connection */
	for (i = 0; i < 3; i++) {
		usleep(200000);

		pkt_tcp.tcp.rst = 1;
		pkt_tcp.iph.payload_len = bpf_htons(sizeof(struct tcphdr));
		pkt_tcp.tcp.check = calc_tcp_cksum(&pkt_tcp);
		tcfg.cpu_core_id = 0;
		tcfg.num_pkts = 1;
		tcfg.pkt_size = offsetof(struct tcp_packet, payload);
		tcfg.prog = test_prog;
		run_traffic(&tcfg);
	}

out:
	if (ai)
		freeaddrinfo(ai);
	if (sock >= 0)
		close(sock);
	if (attached)
		xdp_program__detach(ifindex_prog, cfg->iface.ifindex, cfg->mode, 0);

	xdp_program__close(ifindex_prog);
	xdp_program__close(test_prog);

	xdp_trafficgen__destroy(skel);

	free(runner_threads);
	free(t);
	return err;
}

static const struct probeopt {
	struct iface iface;
} defaults_probe = {};

static struct prog_option probe_options[] = {
	DEFINE_OPTION("interface", OPT_IFNAME, struct probeopt, iface,
		      .metavar = "<ifname>",
		      .short_opt = 'i',
		      .help = "Probe features of device <ifname>"),
	END_OPTIONS
};

int do_probe(const void *opt, __unused const char *pin_root_path)
{
	const struct probeopt *cfg = opt;
	int err1 = 0, err2;

	if (cfg->iface.ifindex) {
		err1 = check_iface_support(&cfg->iface);
		if (err1) {
			const char *name = get_driver_name(cfg->iface.ifindex);
			if (driver_needs_xdp_pass(&cfg->iface)) {
				pr_info(" Note that this driver (%s) needs an XDP program "
					"loaded to use XDP_REDIRECT.\n"
					" Loading a dummy XDP program on the interface "
					"may enable support.\n", name);
			} else {

				if (!strcmp(name, "veth"))
					pr_info(" Note that enabling GRO on both ends of a "
						"veth pair may enable XDP support\n");
			}
		}
	}

	err2 = probe_kernel_support();
	if (!err2)
		pr_info("Kernel supports live packet mode for XDP BPF_PROG_RUN.\n");

	return !(!err1 && !err2);
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-trafficgen COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       udp         - run in UDP mode\n"
		"       xsk-udp     - run in UDP mode (using AF_XDP sockets)\n"
		"       tcp         - run in TCP mode\n"
		"       probe       - probe kernel support\n"
		"       help        - show this help message\n"
		"\n"
		"Use 'xdp-trafficgen COMMAND --help' to see options for each command\n");
	return -1;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(udp, "Run in UDP mode"),
	DEFINE_COMMAND_NAME("xsk-udp", xsk_udp, "Run in UDP mode (using AF_XDP sockets)"),
	DEFINE_COMMAND(tcp, "Run in TCP mode"),
	DEFINE_COMMAND(probe, "Probe kernel support"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct udpopt udp;
	struct tcpopt tcp;
	struct xsk_opts xsk;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
