/* SPDX-License-Identifier: GPL-2.0 */

/*****************************************************************************
 * Include files
 *****************************************************************************/
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <linux/err.h>
#include <linux/ethtool.h>
#include <linux/perf_event.h>
#include <linux/sockios.h>

#include <net/if.h>

#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/dlt.h>
#include <pcap/pcap.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include <xdp/prog_dispatcher.h>

#include "logging.h"
#include "params.h"
#include "util.h"
#include "xdpdump.h"
#include "xpcapng.h"
#include "compat.h"

/*****************************************************************************
 * Local definitions and global variables
 *****************************************************************************/
#define PROG_NAME "xdpdump"
#define DEFAULT_SNAP_LEN 262144

#ifndef ENOTSUPP
#define ENOTSUPP         524 /* Operation is not supported */
#endif

#define RX_FLAG_FENTRY (1<<0)
#define RX_FLAG_FEXIT  (1<<1)

struct flag_val rx_capture_flags[] = {
	{"entry", RX_FLAG_FENTRY},
	{"exit", RX_FLAG_FEXIT},
	{}
};

struct enum_val xdp_modes[] = {
	{"native", XDP_MODE_NATIVE},
	{"skb", XDP_MODE_SKB},
	{"hw", XDP_MODE_HW},
	{"unspecified", XDP_MODE_UNSPEC},
	{NULL, 0}
};

static const struct dumpopt {
	bool                  hex_dump;
	bool                  list_interfaces;
	bool                  load_xdp;
	bool                  promiscuous;
	bool                  use_pcap;
	struct iface          iface;
	uint32_t              perf_wakeup;
	uint32_t              snaplen;
	char                 *pcap_file;
	char                 *program_names;
	unsigned int          load_xdp_mode;
	unsigned int          rx_capture;
} defaults_dumpopt = {
	.hex_dump = false,
	.list_interfaces = false,
	.load_xdp = false,
	.promiscuous = false,
	.use_pcap = false,
	.snaplen = DEFAULT_SNAP_LEN,
	.load_xdp_mode = XDP_MODE_NATIVE,
	.rx_capture = RX_FLAG_FENTRY,
};
struct dumpopt cfg_dumpopt;

static struct prog_option xdpdump_options[] = {
	DEFINE_OPTION("rx-capture", OPT_FLAGS, struct dumpopt, rx_capture,
		      .metavar = "<mode>",
		      .typearg = rx_capture_flags,
		      .help = "Capture point for the rx direction"),
	DEFINE_OPTION("list-interfaces", OPT_BOOL, struct dumpopt,
		      list_interfaces,
		      .short_opt = 'D',
		      .help = "Print the list of available interfaces"),
	DEFINE_OPTION("load-xdp-mode", OPT_ENUM, struct dumpopt, load_xdp_mode,
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Mode used for --load-xdp-mode, default native"),
	DEFINE_OPTION("load-xdp-program", OPT_BOOL, struct dumpopt, load_xdp,
		      .help = "Load XDP trace program if no XDP program is loaded"),
	DEFINE_OPTION("interface", OPT_IFNAME, struct dumpopt, iface,
		      .short_opt = 'i',
		      .metavar = "<ifname>",
		      .help = "Name of interface to capture on"),
#ifdef HAVE_LIBBPF_PERF_BUFFER__CONSUME
	DEFINE_OPTION("perf-wakeup", OPT_U32, struct dumpopt, perf_wakeup,
		      .metavar = "<events>",
		      .help = "Wake up xdpdump every <events> packets"),
#endif
	DEFINE_OPTION("program-names", OPT_STRING, struct dumpopt,
		      program_names,
		      .short_opt = 'p',
		      .metavar = "<prog>",
		      .help = "Specific program to attach to"),
	DEFINE_OPTION("promiscuous-mode", OPT_BOOL, struct dumpopt,
		      promiscuous,
		      .short_opt = 'P',
		      .help = "Open interface in promiscuous mode"),
	DEFINE_OPTION("snapshot-length", OPT_U32, struct dumpopt, snaplen,
		      .short_opt = 's',
		      .metavar = "<snaplen>",
		      .help = "Minimum bytes of packet to capture"),
	DEFINE_OPTION("use-pcap", OPT_BOOL, struct dumpopt, use_pcap,
		      .help = "Use legacy pcap format for XDP traces"),
	DEFINE_OPTION("write", OPT_STRING, struct dumpopt, pcap_file,
		      .short_opt = 'w',
		      .metavar = "<file>",
		      .help = "Write raw packets to pcap file"),
	DEFINE_OPTION("hex", OPT_BOOL, struct dumpopt, hex_dump,
		      .short_opt = 'x',
		      .help = "Print the full packet in hex"),
	END_OPTIONS
};

#define MAX_LOADED_XDP_PROGRAMS  (MAX_DISPATCHER_ACTIONS + 1)

struct capture_programs {
	/* Contains a list of programs to capture on, with the respective
	 * program names. The order MUST be the same as the loaded order!
	 */
	unsigned int nr_of_progs;
	struct prog_info {
		struct xdp_program *prog;
		const char         *func;
		unsigned int        rx_capture;
		/* Fields used by the actual loader. */
		bool                attached;
		int                 perf_map_fd;
		struct bpf_object  *prog_obj;
		struct bpf_link    *fentry_link;
		struct bpf_link    *fexit_link;
	} progs[MAX_LOADED_XDP_PROGRAMS];
};

struct perf_handler_ctx {
	uint64_t                 missed_events;
	uint64_t                 last_missed_events;
	uint64_t                 captured_packets;
	uint64_t                 epoch_delta;
	uint64_t                 packet_id;
	uint64_t                 cpu_packet_id[MAX_CPUS];
	struct dumpopt          *cfg;
	struct capture_programs *xdp_progs;
	pcap_t                  *pcap;
	pcap_dumper_t           *pcap_dumper;
	struct xpcapng_dumper   *pcapng_dumper;
};

bool    exit_xdpdump;
pcap_t *exit_pcap;

/*****************************************************************************
 * get_if_speed()
 *****************************************************************************/
static uint64_t get_if_speed(struct iface *iface)
{
#define MAX_MODE_MASKS 10

	int                                  fd;
	struct ifreq                         ifr;
	struct {
		struct ethtool_link_settings req;
		uint32_t                     modes[3 * MAX_MODE_MASKS];
	} ereq;

	if (iface == NULL)
		return 0;

	/* Open socket, and initialize structures. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;

	memset(&ereq, 0, sizeof(ereq));
	ereq.req.cmd = ETHTOOL_GLINKSETTINGS;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = (void *)&ereq;

	/* First query the kernel to see how many masks we need to ask for. */
	if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
		goto error_exit;

	if (ereq.req.link_mode_masks_nwords >= 0 ||
	    ereq.req.link_mode_masks_nwords < -MAX_MODE_MASKS ||
	    ereq.req.cmd != ETHTOOL_GLINKSETTINGS)
		goto error_exit;

	/* Now ask for the data set, and extract the speed in bps. */
	ereq.req.link_mode_masks_nwords = -ereq.req.link_mode_masks_nwords;
	if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
		goto error_exit;

	/* If speed is unknown return 0. */
	if (ereq.req.speed == -1U)
		ereq.req.speed = 0;

	close(fd);
	return ereq.req.speed * 1000000ULL;

error_exit:
	close(fd);
	return 0;
}

/*****************************************************************************
 * get_if_drv_info()
 *****************************************************************************/
static char *get_if_drv_info(struct iface *iface, char *buffer, size_t len)
{
	int                     fd;
	char                   *r_buffer = NULL;
	struct ifreq            ifr;
	struct ethtool_drvinfo  info;

	if (iface == NULL || buffer == NULL || len == 0)
		return NULL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return NULL;

	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GDRVINFO;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = (void *)&info;

	if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
		goto exit;

	if (try_snprintf(buffer, len,
			 "driver: \"%s\", version: \"%s\", "
			 "fw-version: \"%s\", rom-version: \"%s\", "
			 "bus-info: \"%s\"",
			 info.driver, info.version, info.fw_version,
			 info.erom_version, info.bus_info))
		goto exit;

	r_buffer = buffer;
exit:
	close(fd);
	return r_buffer;
}

/*****************************************************************************
 * set_if_promiscuous_mode()
 *****************************************************************************/
static int set_if_promiscuous_mode(struct iface *iface, bool enable,
				   bool *did_enable)
{
	int          fd;
	int          rc = 0;
	struct ifreq ifr;

	if (iface == NULL)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		pr_debug("DBG: Failed getting promiscuous mode: %s\n",
			 strerror(errno));
		rc = -errno;
		goto exit;
	}
	if (((ifr.ifr_flags & IFF_PROMISC) && enable) ||
	    (!(ifr.ifr_flags & IFF_PROMISC) && !enable)) {
		pr_debug("DBG: Promiscuous mode already %s!\n",
			 enable ? "on" : "off");
		goto exit;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~IFF_PROMISC;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		pr_debug("DBG: Failed setting promiscuous mode %s: %s\n",
			 enable ? "on" : "off", strerror(errno));
		rc = -errno;
		goto exit;
	}

	if (did_enable) {
		if (enable)
			*did_enable = true;
		else
			*did_enable = false;
	}
exit:
	close(fd);
	return rc;
}

/*****************************************************************************
 * get_xdp_return_string()
 *****************************************************************************/
static const char *get_xdp_action_string(enum xdp_action act)
{
	switch (act) {
	case XDP_ABORTED:
		return "[ABORTED]";
	case XDP_DROP:
		return "[DROP]";
	case XDP_PASS:
		return "[PASS]";
	case XDP_TX:
		return "[TX]";
	case XDP_REDIRECT:
		return "[REDIRECT]";
	}
	return "[*unknown*]";
}

/*****************************************************************************
 * get_capture_mode_string()
 *****************************************************************************/
static const char *get_capture_mode_string(unsigned int mode)
{
	switch(mode) {
	case RX_FLAG_FENTRY:
		return "entry";
	case RX_FLAG_FEXIT:
		return "exit";
	case RX_FLAG_FENTRY | RX_FLAG_FEXIT:
		return "entry/exit";
	}
	return "unknown";
}

/*****************************************************************************
 * snprinth()
 *****************************************************************************/
#define SNPRINTH_MIN_BUFFER_SIZE sizeof("0xffff:  00 11 22 33 44 55 66 77 88" \
					" 99 aa bb cc dd ee ff	" \
					"................0")

static int snprinth(char *str, size_t size,
		    const uint8_t *buffer, size_t buffer_size, size_t offset)
{
	int i;
	int pre_skip;
	int post_skip;
	size_t zero_offset;

	if (str == NULL || size < SNPRINTH_MIN_BUFFER_SIZE ||
	    buffer == NULL || offset >= buffer_size || buffer_size > 0xffff)
		return -EINVAL;

	zero_offset = offset & ~0xf;
	pre_skip = offset & 0xf;
	post_skip = (zero_offset + 0xf) < buffer_size ? \
		0 : 16 - (buffer_size - zero_offset);

	/* Print offset */
	snprintf(str, size, "0x%04zx:  ", offset & 0xfff0);
	str += 9;

	/* Print hex values */
	if (pre_skip) {
		memset(str, ' ', pre_skip * 3);
		str[pre_skip * 3] = 0;
	}

	for (i = pre_skip; i < 16 - post_skip; i++) {
		snprintf(str + (i * 3), 5, "%02x ",
			 buffer[zero_offset + i]);
	}

	if (post_skip) {
		memset(str + (i * 3), ' ', post_skip * 3);
		str[(i * 3) + (post_skip * 3)] = 0;
	}

	/* Print printable chars */
	str += 16 * 3;
	*str++ = ' ';

	if (pre_skip) {
		memset(str, ' ', pre_skip);
		str[pre_skip] = 0;
	}
	for (i = pre_skip; i < 16 - post_skip; i++)
		str[i] = isprint(buffer[zero_offset + i]) ? \
			buffer[zero_offset + i]: '.';

	str[i] = 0;
	return 0;
}

/*****************************************************************************
 * handle_perf_event()
 *****************************************************************************/
static enum bpf_perf_event_ret handle_perf_event(void *private_data,
						 int cpu,
						 struct perf_event_header *event)
{
	uint64_t                  ts;
	bool                      fexit;
	unsigned int              if_idx, prog_idx;
	const char               *xdp_func;
	struct perf_handler_ctx  *ctx = private_data;
	struct perf_sample_event *e = container_of(event,
						   struct perf_sample_event,
						   header);
	struct perf_lost_event   *lost = container_of(event,
						      struct perf_lost_event,
						      header);

	switch(e->header.type) {
	case PERF_RECORD_SAMPLE:

		if (cpu >= MAX_CPUS ||
		    e->header.size < sizeof(struct perf_sample_event) ||
		    e->size < (sizeof(struct pkt_trace_metadata) + e->metadata.cap_len) ||
		    e->metadata.prog_index >= ctx->xdp_progs->nr_of_progs)
			return LIBBPF_PERF_EVENT_CONT;

		fexit = e->metadata.flags & MDF_DIRECTION_FEXIT;
		prog_idx = e->metadata.prog_index;
		if_idx = prog_idx * 2 + (fexit ? 1 : 0);
		xdp_func = ctx->xdp_progs->progs[prog_idx].func;

		if (prog_idx == 0 &&
		    (!fexit ||
		     ctx->xdp_progs->progs[prog_idx].rx_capture == RX_FLAG_FEXIT))
			ctx->cpu_packet_id[cpu] = ++ctx->packet_id;

		ts = e->time + ctx->epoch_delta;

		if (ctx->pcapng_dumper) {
			struct xpcapng_epb_options_s options = {};
			int64_t  action = e->metadata.action;
			uint32_t queue = e->metadata.rx_queue;

			options.flags = PCAPNG_EPB_FLAG_INBOUND;
			options.dropcount = ctx->last_missed_events;
			options.packetid = &ctx->cpu_packet_id[cpu];
			options.queue = &queue;
			options.xdp_verdict = fexit ? &action : NULL;

			xpcapng_dump_enhanced_pkt(ctx->pcapng_dumper,
						  if_idx,
						  e->packet,
						  e->metadata.pkt_len,
						  min(e->metadata.cap_len,
						      ctx->cfg->snaplen),
						  ts,
						  &options);

			ctx->last_missed_events = 0;
			if (ctx->cfg->pcap_file[0] == '-' &&
			    ctx->cfg->pcap_file[1] == 0)
				xpcapng_dump_flush(ctx->pcapng_dumper);
		} else if (ctx->pcap_dumper) {
			struct pcap_pkthdr h;

			h.ts.tv_sec = ts / 1000000000ULL;
			h.ts.tv_usec = ts % 1000000000ULL / 1000;
			h.caplen = min(e->metadata.cap_len, ctx->cfg->snaplen);
			h.len = e->metadata.pkt_len;
			pcap_dump((u_char *) ctx->pcap_dumper, &h,
				  e->packet);

			if (ctx->cfg->pcap_file[0] == '-' &&
			    ctx->cfg->pcap_file[1] == 0)
				pcap_dump_flush(ctx->pcap_dumper);
		} else {
			int  i;
			char hline[SNPRINTH_MIN_BUFFER_SIZE];

			if (ctx->cfg->hex_dump) {
				printf("%llu.%09lld: %s()@%s%s: packet size %u "
				       "bytes, captured %u bytes on if_index "
				       "%u, rx queue %u, id %"PRIu64"\n",
				       ts / 1000000000ULL,
				       ts % 1000000000ULL,
				       xdp_func,
				       fexit ? "exit" : "entry",
				       fexit ? get_xdp_action_string(
					       e->metadata.action) : "",
				       e->metadata.pkt_len,
				       e->metadata.cap_len,
				       e->metadata.ifindex,
				       e->metadata.rx_queue,
				       ctx->cpu_packet_id[cpu]);

				for (i = 0; i < e->metadata.cap_len; i += 16) {
					snprinth(hline, sizeof(hline),
						 e->packet,
						 e->metadata.cap_len, i);
					printf("  %s\n", hline);
				}
			} else {
				printf("%llu.%09lld: %s()@%s%s: packet size %u "
				       "bytes on if_index %u, rx queue %u, "
				       "id %"PRIu64"\n",
				       ts / 1000000000ULL,
				       ts % 1000000000ULL,
				       xdp_func,
				       fexit ? "exit" : "entry",
				       fexit ? get_xdp_action_string(
					       e->metadata.action) : "",
				       e->metadata.pkt_len,e->metadata.ifindex,
				       e->metadata.rx_queue,
				       ctx->cpu_packet_id[cpu]);
			}
		}
		ctx->captured_packets++;
		break;

	case PERF_RECORD_LOST:
		ctx->missed_events += lost->lost;
		ctx->last_missed_events += lost->lost;
		break;
	}

	return LIBBPF_PERF_EVENT_CONT;
}

/*****************************************************************************
 * get_epoch_to_uptime_delta()
 *****************************************************************************/
static int get_epoch_to_uptime_delta(uint64_t *delta)
{
	/* This function will calculate the rough delta between uptime
	 * seconds and the epoch time. This is not a precise delta as there is
	 * a delay between calling the two functions below (and time() being in
	 * seconds), but it's good enough to get a general offset. The delta
	 * between packets is still based on the timestamps from the trace
	 * infrastructure.
	 */
	struct timespec ts;
	uint64_t        uptime;
	uint64_t        epoch = time(NULL) * 1000000000ULL;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		pr_warn("ERROR: Failed to get CLOCK_MONOTONIC time: %s(%d)",
			strerror(errno), errno);
		return -errno;
	}
	uptime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	*delta = epoch - uptime;
	return 0;
}

/*****************************************************************************
 * capture_on_legacy_interface()
 *****************************************************************************/
static bool capture_on_legacy_interface(struct dumpopt *cfg)
{
	bool              rc = false;
	char              errbuf[PCAP_ERRBUF_SIZE];
	uint64_t          captured_packets = 0;
	pcap_t           *pcap = NULL;
	pcap_dumper_t    *pcap_dumper = NULL;
	struct pcap_stat  ps;

	/* Open pcap handle for live capture. */
	if (cfg->rx_capture != RX_FLAG_FENTRY) {
		pr_warn("ERROR: For legacy capture only \"--rx-capture entry\""
			" is supported!\n");
		goto error_exit;
	}

	pcap = pcap_open_live(cfg->iface.ifname, cfg->snaplen,
			      cfg->promiscuous, 1000, errbuf);
	if (pcap == NULL) {
		pr_warn("ERROR: Can't open pcap live interface: %s\n", errbuf);
		goto error_exit;
	}

	/* Open the pcap handle for pcap file. */
	if (cfg->pcap_file) {
		pcap_dumper = pcap_dump_open(pcap, cfg->pcap_file);
		if (!pcap_dumper) {
			pr_warn("ERROR: Can't open pcap file for writing!\n");
			goto error_exit;
		}
	}

	/* No more error conditions, display some capture information */
	fprintf(stderr, "listening on %s, link-type %s (%s), "
		"capture size %d bytes\n", cfg->iface.ifname,
		pcap_datalink_val_to_name(pcap_datalink(pcap)),
		pcap_datalink_val_to_description(pcap_datalink(pcap)),
		cfg->snaplen);

	/* Loop for receive packets on live interface. */
	exit_pcap = pcap;
	while (!exit_xdpdump) {
		const uint8_t      *packet;
		struct pcap_pkthdr  h;

		packet = pcap_next(pcap, &h);
		if (!packet)
			continue;

		if (pcap_dumper) {
			pcap_dump((u_char *) pcap_dumper, &h, packet);

			if (cfg->pcap_file[0] == '-' && cfg->pcap_file[1] == 0)
				pcap_dump_flush(pcap_dumper);
		} else {
			size_t i;
			char hline[SNPRINTH_MIN_BUFFER_SIZE];

			if (cfg->hex_dump) {
				printf("%ld.%06ld: packet size %u bytes, "
				       "captured %u bytes on if_name \"%s\"\n",
				       (long) h.ts.tv_sec, (long) h.ts.tv_usec,
				       h.len, h.caplen, cfg->iface.ifname);

				for (i = 0; i < h.caplen; i += 16) {
					snprinth(hline, sizeof(hline),
						 packet, h.caplen, i);
					printf("  %s\n", hline);
				}
			} else {
				printf("%ld.%06ld: packet size %u bytes on "
				       "if_name \"%s\"\n",
				       (long) h.ts.tv_sec, (long) h.ts.tv_usec,
				       h.len, cfg->iface.ifname);
			}
		}
		captured_packets++;
	}
	exit_pcap = NULL;
	rc = true;

	fprintf(stderr, "\n%"PRIu64" packets captured\n", captured_packets);
	if (pcap_stats(pcap, &ps) == 0) {
		fprintf(stderr, "%u packets dropped by kernel\n", ps.ps_drop);
		if (ps.ps_ifdrop != 0)
			fprintf(stderr, "%u packets dropped by interface\n",
				ps.ps_ifdrop);
	}

error_exit:

	if (pcap_dumper)
		pcap_dump_close(pcap_dumper);

	if (pcap)
		pcap_close(pcap);

	return rc;
}

/*****************************************************************************
 * append_snprintf()
 *****************************************************************************/
int append_snprintf(char **buf, size_t *buf_len, size_t *offset,
		    const char *format, ...)
{
	int     len;
	va_list args;

	if (buf == NULL || *buf == NULL || buf_len == NULL || *buf_len <= 0 ||
	    offset == NULL || *buf_len - *offset <= 0)
		return -EINVAL;

	while (true) {
		char   *new_buf;
		size_t  new_buf_len;

		va_start(args, format);
		len = vsnprintf(*buf + *offset, *buf_len - *offset, format, args);
		va_end(args);

		if ((size_t)len < (*buf_len - *offset)) {
			*offset += len;
			len = 0;
			break;
		}

		if (*buf_len >= 2048)
			return -ENOMEM;

		new_buf_len = *buf_len * 2;
		new_buf = realloc(*buf, new_buf_len);

		if (!new_buf)
			return -ENOMEM;

		*buf = new_buf;
		*buf_len = new_buf_len;
	}
	return len;
}

/*****************************************************************************
 * get_program_names_all()
 *****************************************************************************/
static char *get_program_names_all(struct capture_programs *progs, int skip_index)
{
	char   *program_names;
	size_t  size = 128;
	size_t  offset = 0;

	program_names = malloc(size);
	if (!program_names)
		return NULL;

	for (unsigned int i = 0; i < progs->nr_of_progs; i++) {
		const char *kname = xdp_program__name(progs->progs[i].prog);
		const char *fname = progs->progs[i].func;
		uint32_t id = xdp_program__id(progs->progs[i].prog);

		if (skip_index != (int)i) {
			if (append_snprintf(&program_names, &size, &offset,
					    "%s%s@%d", i == 0 ? "" : ",",
					    fname ? fname : kname, id) < 0) {
				free(program_names);
				return NULL;
			}
		} else {
			if (append_snprintf(&program_names, &size, &offset,
					    "%s%s@%d", i == 0 ? "" : ",",
					    "<function_name>", id) < 0) {
				free(program_names);
				return NULL;
			}
		}
	}
	return program_names;
}

/*****************************************************************************
 * find_func_matches()
 *****************************************************************************/
static size_t find_func_matches(const struct btf *btf,
				const char *func_name,
				const char **found_name,
				bool print, int print_id, bool exact)
{
	const struct btf_type *t, *match;
	size_t len, matches = 0;
	const char *name;
	int nr_types, i;

	if (!btf) {
		pr_debug("No BTF found for program\n");
		return 0;
	}

	len = strlen(func_name);

	nr_types = btf__type_cnt(btf);
	for (i = 1; i < nr_types; i++) {
		t = btf__type_by_id(btf, i);
		if (!btf_is_func(t))
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (!strncmp(name, func_name, len)) {
			pr_debug("Found func %s matching %s\n",
				 name, func_name);

			if (print) {
				if (print_id < 0)
					pr_warn("  %s\n", name);
				else
					pr_warn("  %s@%d\n", name, print_id);
			}

			/* Do an exact match if the user specified a function
			 * name, or if there is no possibility of truncation
			 * because the length is different from the truncated
			 * length.
			 */
			if (strlen(name) == len &&
			    (exact || len != BPF_OBJ_NAME_LEN - 1)) {
				*found_name = name;
				return 1; /* exact match */
			}

			/* prefix, may not be unique */
			matches++;
			match = t;
		}
	}

	if (exact)
		return 0;

	if (matches == 1)
		*found_name = btf__name_by_offset(btf, match->name_off);

	return matches;
}

/*****************************************************************************
 * match_target_function()
 *****************************************************************************/
static int match_target_function(struct dumpopt *cfg,
				 struct capture_programs *all_progs,
				 char *prog_name, int prog_id)
{
	int          i;
	unsigned int matches = 0;

	for (i = 0; i < (int)all_progs->nr_of_progs; i++) {
		const char *kname = xdp_program__name(all_progs->progs[i].prog);

		if (prog_id != -1 &&
		    xdp_program__id(all_progs->progs[i].prog) != (uint32_t) prog_id)
			continue;

		if (!strncmp(kname, prog_name, strlen(kname))) {
			if (all_progs->progs[i].func == NULL) {
				if (find_func_matches(xdp_program__btf(all_progs->progs[i].prog),
						      prog_name,
						      &all_progs->progs[i].func,
						      false, -1,
						      true) == 1) {
					all_progs->progs[i].rx_capture = cfg->rx_capture;
					matches++;
				} else if (strlen(prog_name) <= BPF_OBJ_NAME_LEN - 1) {
					/* If the user cut and paste the
					 * truncated function name, make sure
					 * we tell him all the possible options!
					 */
					matches = UINT_MAX;
					break;
				}
			} else if (!strcmp(all_progs->progs[i].func, prog_name)) {
				all_progs->progs[i].rx_capture = cfg->rx_capture;
				matches++;
			}
		}
		if (prog_id != -1)
			break;
	}

	if (!matches) {
		if (prog_id == -1)
			pr_warn("ERROR: Can't find function '%s' on interface!\n",
				prog_name);
		else
			pr_warn("ERROR: Can't find function '%s' in interface program %d!\n",
				prog_name, prog_id);

		return -ENOENT;
	} else if (matches == 1) {
		return 0;
	}

	if (matches != UINT_MAX) {
		pr_warn("ERROR: The function '%s' exists in multiple programs!\n",
			prog_name);
	} else {
		if (prog_id == -1)
			pr_warn("ERROR: Can't identify the full XDP '%s' function!\n",
				prog_name);
		else
			pr_warn("ERROR: Can't identify the full XDP '%s' function in program %d!\n",
				prog_name, prog_id);
	}
	pr_warn("The following is a list of candidates:\n");

	for (i = 0; i < (int)all_progs->nr_of_progs; i++) {
		uint32_t    cur_prog_id = xdp_program__id(all_progs->progs[i].prog);
		const char *func_dummy;

		if (prog_id != -1 && cur_prog_id != (uint32_t) prog_id)
			continue;

		find_func_matches(xdp_program__btf(all_progs->progs[i].prog),
				  xdp_program__name(all_progs->progs[i].prog),
				  &func_dummy, true,
				  (prog_id == -1 &&
				   matches == UINT_MAX) ? -1 : (int) cur_prog_id,
				  false);

		if (prog_id != -1)
			break;
	}

	pr_warn("Please use the -p option to pick the correct one.\n");
	if (!strcmp("all", cfg->program_names)) {
		char *program_names = get_program_names_all(all_progs, i);

		if (program_names) {
			pr_warn("Command line to replace 'all':\n  %s\n",
				program_names);
			free(program_names);
		}
	}

	return -EAGAIN;
}


/*****************************************************************************
 * check_btf()
 *****************************************************************************/
static bool check_btf(struct xdp_program *prog)
{
	if (xdp_program__btf(prog))
		return true;

	pr_warn("ERROR: xdpdump requires BTF information, but that is missing "
		"from the loaded XDP program!\n");
	return false;
}

/*****************************************************************************
 * find_target()
 *
 * What is this function trying to do? It will return a list of programs to
 * capture on, based on the configured program-names. If this parameter is
 * not given, it will attach to the first (main) program.
 *
 * Note that the kernel API will truncate function names at BPF_OBJ_NAME_LEN
 * so we need to guess the correct function if not explicitly given with
 * the program-names option.
 *
 *****************************************************************************/
static int find_target(struct dumpopt *cfg, struct xdp_multiprog *mp,
		       struct capture_programs *tgt_progs)
{
	const char              *func;
	struct xdp_program      *prog, *p;
	struct capture_programs  progs;
	size_t                   matches;
	char                    *prog_name;
	char                    *prog_safe_ptr;
	char                    *program_names = cfg->program_names;

	prog = xdp_multiprog__main_prog(mp);
	if (!check_btf(prog))
		return -EINVAL;

	/* First take care of the default case, i.e. no function supplied */
	if (!program_names) {
		/* The libxdp code optimization where it skips the dispatcher
		 * if only one program is loaded. If this is the case, we need
		 * to attach to the actual first program, not the dispatcher.
		 */
		if (xdp_multiprog__program_count(mp) == 1) {
			prog = xdp_multiprog__next_prog(NULL, mp);

			if (!check_btf(prog))
				return -EINVAL;
		}

		matches = find_func_matches(xdp_program__btf(prog),
					    xdp_program__name(prog),
					    &func, false, -1, false);

		if (!matches) {
			pr_warn("ERROR: Can't find function '%s' on interface!\n",
				xdp_program__name(prog));
			return -ENOENT;
		} else if (matches == 1) {
			tgt_progs->nr_of_progs = 1;
			tgt_progs->progs[0].prog = prog;
			tgt_progs->progs[0].func = func;
			tgt_progs->progs[0].rx_capture = cfg->rx_capture;
			return 0;
		}

		pr_warn("ERROR: Can't identify the full XDP main function!\n"
			"The following is a list of candidates:\n");

		find_func_matches(xdp_program__btf(prog),
				  xdp_program__name(prog),
				  &func, true, -1, false);

		pr_warn("Please use the -p option to pick the correct one.\n");
		return -EAGAIN;
	}

	/* We end up here if we have a configured function(s), which can be
	 * any function in one of the programs attached. In the case of
	 * multiple programs we can even have duplicate functions amongst
	 * programs and we need a way to differentiate. We do this by
	 * supplying the @<program_id>. See the -D output for the program IDs.
	 * We also have the "all" keyword, which will specify that all
	 * functions need to be traced.
	 */

	/* Fill in the all_prog data structure to make matching easier */
	memset(&progs, 0, sizeof(progs));

	progs.progs[progs.nr_of_progs].prog = prog;
	matches = find_func_matches(xdp_program__btf(prog),
				    xdp_program__name(prog),
				    &progs.progs[progs.nr_of_progs].func,
				    false, -1, false);
	if (matches != 1)
		progs.progs[progs.nr_of_progs].func = NULL;
	progs.nr_of_progs++;

	for (p = xdp_multiprog__next_prog(NULL, mp);
	     p;
	     p = xdp_multiprog__next_prog(p, mp)) {

		progs.progs[progs.nr_of_progs].prog = p;
		matches = find_func_matches(xdp_program__btf(p),
					    xdp_program__name(p),
					    &progs.progs[progs.nr_of_progs].func,
					    false, -1, false);
		if (matches != 1)
			progs.progs[progs.nr_of_progs].func = NULL;
		progs.nr_of_progs++;

		if (progs.nr_of_progs >= MAX_LOADED_XDP_PROGRAMS)
			break;
	}

	/* If "all" option is specified create temp program names */
	if (!strcmp("all", program_names)) {
		program_names = get_program_names_all(&progs, -1);
		if (!program_names) {
			pr_warn("ERROR: Out of memory for 'all' programs!\n");
			return -ENOMEM;
		}
	}

	/* Split up the --program-names and walk over it */
	for (prog_name = strtok_r(program_names, ",", &prog_safe_ptr);
	     prog_name != NULL;
	     prog_name = strtok_r(NULL, ",", &prog_safe_ptr)) {

		int   rc;
		unsigned long id = -1;
		char *id_str = strchr(prog_name, '@');
		char *alloc_name = NULL;

		if (id_str) {
			unsigned int  i;
			char         *endptr;

			errno = 0;
			id_str++;
			id = strtoul(id_str, &endptr, 10);
			if ((errno == ERANGE && id == ULONG_MAX)
			    || (errno != 0 && id == 0) || *endptr != '\0'
			    || endptr == id_str) {

				pr_warn("ERROR: Can't extract valid program id from \"%s\"!\n",
					prog_name);
				if (cfg->program_names != program_names)
					free(program_names);
				return -EINVAL;
			}

			for (i = 0; i < progs.nr_of_progs; i++) {
				if (id == xdp_program__id(progs.progs[i].prog))
					break;
			}
			if (i >= progs.nr_of_progs) {
				pr_warn("ERROR: Invalid program id supplied, \"%s\"!\n",
					prog_name);
				if (cfg->program_names != program_names)
					free(program_names);
				return -EINVAL;
			}

			alloc_name = strndup(prog_name,
					     id_str - prog_name - 1);
			if (!alloc_name) {
				pr_warn("ERROR: Out of memory while processing program-name argument!\n");
				if (cfg->program_names != program_names)
					free(program_names);
				return -ENOMEM;
			}
			prog_name = alloc_name;
		} else {
			/* If no @id was specified, verify if the program name
			 * was not a program_id. If so, locate the name and
			 * use it in the lookup below.
			 */
			char *endptr;
			unsigned long prog_id;

			prog_id = strtoul(prog_name, &endptr, 10);
			if (!((errno == ERANGE && prog_id == ULONG_MAX)
			      || (errno != 0 && prog_id == 0) || *endptr != '\0'
			      || endptr == prog_name)) {

				for (unsigned int i = 0; i < progs.nr_of_progs; i++) {
					if (prog_id == xdp_program__id(progs.progs[i].prog)) {
						alloc_name = strdup(progs.progs[i].func);
						if (alloc_name) {
							id = prog_id;
							prog_name = alloc_name;
						}
						break;
					}
				}
			}
		}

		rc = match_target_function(cfg, &progs, prog_name, id);
		free(alloc_name);
		if (rc < 0) {
			if (cfg->program_names != program_names)
				free(program_names);
			return rc;
		}
	}

#if 0
	/* Removed this optimization for now as it will save one packet when
	 * three programs are loaded, two for four, etc. In addition, it will
	 * make the packet flow looks a bit weird, without it's more clear
	 *  which programs the dispatcher has executed.
	 */
	if (cfg->rx_capture == (RX_FLAG_FENTRY | RX_FLAG_FEXIT)) {
		/* If we do entry and exit captures we can remove fentry from
		 * back to back programs to skip storing an identical packet.
		 * We keep fexit due to the reported return code.
		 *
		 * First program is the dispatches (which should not modify
		 * the packet, but we can't be sure). So we skip this and the
		 * first sub-programs fexit).
		 */
		for (int i = 2; i < progs.nr_of_progs; i++)
			if (progs.progs[i-1].rx_capture & RX_FLAG_FENTRY)
				progs.progs[i].rx_capture &= ~RX_FLAG_FENTRY;
	}
#endif

	if (cfg->program_names != program_names)
		free(program_names);

	/* Copy all the programs that need capture actions */
	memset(tgt_progs, 0, sizeof(*tgt_progs));
	for (unsigned int i = 0; i < progs.nr_of_progs; i++) {
		if (!progs.progs[i].rx_capture)
			continue;

		tgt_progs->progs[tgt_progs->nr_of_progs].prog = progs.progs[i].prog;
		tgt_progs->progs[tgt_progs->nr_of_progs].func = progs.progs[i].func;
		tgt_progs->progs[tgt_progs->nr_of_progs].rx_capture = progs.progs[i].rx_capture;
		tgt_progs->nr_of_progs++;
	}
	return 0;
}

/*****************************************************************************
 * get_loaded_program_info()
 *****************************************************************************/
static char *get_loaded_program_info(struct dumpopt *cfg)
{
	char                *info;
	size_t               info_size = 128;
	size_t               info_offset = 0;
	struct xdp_multiprog *mp = NULL;

	info = malloc(info_size);
	if (!info)
		return NULL;

	if (append_snprintf(&info, &info_size, &info_offset,
			    "Capture was taken on interface %s, with the "
			    "following XDP programs loaded:\n",
			    cfg->iface.ifname) < 0)
		goto error_out;

	mp = xdp_multiprog__get_from_ifindex(cfg->iface.ifindex);
	if (IS_ERR_OR_NULL(mp)) {
		if (append_snprintf(&info, &info_size, &info_offset,
				    "  %s()\n", "<No XDP program loaded!>"))
			goto error_out;
	} else {
		struct xdp_program *prog = NULL;

		if (append_snprintf(&info, &info_size, &info_offset, "  %s()\n",
				    xdp_program__name(
					    xdp_multiprog__main_prog(mp))) < 0)
			goto error_out;

		while ((prog = xdp_multiprog__next_prog(prog, mp))) {
			if (append_snprintf(&info, &info_size, &info_offset,
					    "    %s()\n",
					    xdp_program__name(prog)) < 0)
				goto error_out;
		}

		xdp_multiprog__close(mp);
	}
	return info;

error_out:
	xdp_multiprog__close(mp);
	free(info);
	return NULL;
}

/*****************************************************************************
 * add_interfaces_to_pcapng()
 *****************************************************************************/
static bool add_interfaces_to_pcapng(struct dumpopt *cfg,
				     struct xpcapng_dumper *pcapng_dumper,
				     struct capture_programs *progs)
{
	uint64_t if_speed;
	char     if_drv[260];

	if_speed = get_if_speed(&cfg->iface);
	if_drv[0] = 0;
	get_if_drv_info(&cfg->iface, if_drv, sizeof(if_drv));

	for (unsigned int i = 0; i < progs->nr_of_progs; i++) {
		char if_name[128];

		if (try_snprintf(if_name, sizeof(if_name), "%s:%s()@fentry",
				 cfg->iface.ifname, progs->progs[i].func)) {
			pr_warn("ERROR: Could not format interface name, %s:%s()@fentry!\n",
				cfg->iface.ifname, progs->progs[i].func);
			return false;
		}

		if (xpcapng_dump_add_interface(pcapng_dumper,
					       cfg->snaplen,
					       if_name, NULL, NULL,
					       if_speed,
					       9 /* nsec resolution */,
					       if_drv) < 0) {
			pr_warn("ERROR: Can't add %s interface to PcapNG file!\n",
				if_name);
			return false;
		}

		if (try_snprintf(if_name, sizeof(if_name), "%s:%s()@fexit",
				 cfg->iface.ifname, progs->progs[i].func)) {
			pr_warn("ERROR: Could not format interface name, %s:%s()@fexit!\n",
				cfg->iface.ifname, progs->progs[i].func);
			return false;
		}

		if (xpcapng_dump_add_interface(pcapng_dumper,
					       cfg->snaplen,
					       if_name, NULL, NULL,
					       if_speed,
					       9 /* nsec resolution */,
					       if_drv) < 0) {
			pr_warn("ERROR: Can't add %s interface to PcapNG file!\n",
				if_name);
			return false;
		}
	}
	return true;
}

static void print_compat_error(const char *what)
{
#if defined(__x86_64__) || defined(__i686__)
	pr_warn("ERROR: The kernel does not support "
		"fentry %s because it is too old!", what);
#else
	pr_warn("ERROR: The kernel does not support "
		"fentry %s on the current CPU architecture!", what);
#endif
}

/*****************************************************************************
 * load_and_attach_trace()
 *****************************************************************************/
static bool load_and_attach_trace(struct dumpopt *cfg,
				  struct capture_programs *progs,
				  unsigned int idx)
{
	int                          err;
	struct bpf_object           *trace_obj = NULL;
	struct bpf_program          *trace_prog_fentry;
	struct bpf_program          *trace_prog_fexit;
	struct bpf_link             *trace_link_fentry = NULL;
	struct bpf_link             *trace_link_fexit = NULL;
	struct bpf_map              *perf_map;
	struct bpf_map              *data_map;
	struct trace_configuration   trace_cfg;

	if (idx >= progs->nr_of_progs || progs->nr_of_progs == 0) {
		pr_warn("ERROR: Attach program ID invalid!\n");
		return false;
	}

	progs->progs[idx].attached = false;

	if (progs->progs[idx].rx_capture == 0) {
		pr_warn("ERROR: No RX capture mode to attach to!\n");
		return false;
	}

	silence_libbpf_logging();

rlimit_loop:
	/* Load the trace program object */
	trace_obj = open_bpf_file("xdpdump_bpf.o", NULL);
	err = libbpf_get_error(trace_obj);
	if (err) {
		pr_warn("ERROR: Can't open XDP trace program: %s(%d)\n",
			strerror(-err), err);
		trace_obj = NULL;
		goto error_exit;
	}

	/* Set the ifIndex in the DATA map */
	data_map = bpf_object__find_map_by_name(trace_obj, "xdpdump_.data");
	if (!data_map) {
		pr_warn("ERROR: Can't find the .data MAP in the trace "
			"program!\n");
		goto error_exit;
	}

	if (bpf_map__value_size(data_map) != sizeof(trace_cfg)) {
		pr_warn("ERROR: Can't find the correct sized .data MAP in the "
			"trace program!\n");
		goto error_exit;
	}

	trace_cfg.capture_if_ifindex = cfg->iface.ifindex;
	trace_cfg.capture_snaplen = cfg->snaplen;
	trace_cfg.capture_prog_index = idx;
	if (bpf_map__set_initial_value(data_map, &trace_cfg,
				       sizeof(trace_cfg))) {
		pr_warn("ERROR: Can't set initial .data MAP in the trace "
			"program!\n");
		goto error_exit;
	}

	/* Locate the fentry and fexit functions */
	trace_prog_fentry = bpf_object__find_program_by_name(trace_obj,
							     "trace_on_entry");
	if (!trace_prog_fentry) {
		pr_warn("ERROR: Can't find XDP trace fentry function!\n");
		goto error_exit;
	}

	trace_prog_fexit = bpf_object__find_program_by_name(trace_obj,
							    "trace_on_exit");
	if (!trace_prog_fexit) {
		pr_warn("ERROR: Can't find XDP trace fexit function!\n");
		goto error_exit;
	}

	/* Before we can load the object in memory we need to set the attach
	 * point to our function. */
	bpf_program__set_expected_attach_type(trace_prog_fentry,
					      BPF_TRACE_FENTRY);
	bpf_program__set_expected_attach_type(trace_prog_fexit,
					      BPF_TRACE_FEXIT);
	bpf_program__set_attach_target(trace_prog_fentry,
				       xdp_program__fd(progs->progs[idx].prog),
				       progs->progs[idx].func);
	bpf_program__set_attach_target(trace_prog_fexit,
				       xdp_program__fd(progs->progs[idx].prog),
				       progs->progs[idx].func);

	/* Reuse the xdpdump_perf_map for all programs */
	perf_map = bpf_object__find_map_by_name(trace_obj,
						"xdpdump_perf_map");
	if (!perf_map) {
		pr_warn("ERROR: Can't find xdpdump_perf_map in trace program!\n");
		goto error_exit;
	}
	if (idx != 0) {
		err = bpf_map__reuse_fd(perf_map, progs->progs[0].perf_map_fd);
		if (err) {
			pr_warn("ERROR: Can't reuse xdpdump_perf_map: %s\n",
				strerror(-err));
			goto error_exit;
		}
	}

	/* Load the bpf object into memory */
	err = bpf_object__load(trace_obj);
	if (err) {
		if (err == -EPERM && !double_rlimit()) {
			bpf_object__close(trace_obj);
			goto rlimit_loop;
		} else if (err == -E2BIG) {
			print_compat_error("function load");
		} else {
			char err_msg[STRERR_BUFSIZE];

			libbpf_strerror(err, err_msg, sizeof(err_msg));
			pr_warn("ERROR: Can't load eBPF object: %s(%d)\n",
				err_msg, err);
		}
		goto error_exit;
	}

	/* Attach trace programs only in the direction(s) needed */
	if (progs->progs[idx].rx_capture & RX_FLAG_FENTRY) {
		trace_link_fentry = bpf_program__attach_trace(trace_prog_fentry);
		err = libbpf_get_error(trace_link_fentry);
		if (err) {
			if (err == -ENOTSUPP)
				print_compat_error("function attach");
			else
				pr_warn("ERROR: Can't attach XDP trace fentry "
					"function: %s\n",
					strerror(-err));
			goto error_exit;
		}
	}

	if (progs->progs[idx].rx_capture & RX_FLAG_FEXIT) {
		trace_link_fexit = bpf_program__attach_trace(trace_prog_fexit);
		err = libbpf_get_error(trace_link_fexit);
		if (err) {
			pr_warn("ERROR: Can't attach XDP trace fexit function: %s\n",
				strerror(-err));
			goto error_exit;
		}
	}

	/* Figure out the fd for the BPF_MAP_TYPE_PERF_EVENT_ARRAY trace map. */
	if (idx == 0) {
		progs->progs[idx].perf_map_fd = bpf_map__fd(perf_map);
		if (progs->progs[idx].perf_map_fd < 0) {
			pr_warn("ERROR: Can't get xdpdump_perf_map file descriptor: %s\n",
				strerror(errno));
			return false;
		}
	} else {
		progs->progs[idx].perf_map_fd = progs->progs[0].perf_map_fd;
	}

	progs->progs[idx].attached = true;
	progs->progs[idx].fentry_link = trace_link_fentry;
	progs->progs[idx].fexit_link = trace_link_fexit;
	progs->progs[idx].prog_obj = trace_obj;
	return true;

error_exit:
	bpf_link__destroy(trace_link_fentry);
	bpf_link__destroy(trace_link_fexit);
	bpf_object__close(trace_obj);
	return false;
}

/*****************************************************************************
 * load_and_attach_traces()
 *****************************************************************************/
static bool load_and_attach_traces(struct dumpopt *cfg,
				   struct capture_programs *progs)
{
	for (unsigned int i = 0; i < progs->nr_of_progs; i++)
		if (!load_and_attach_trace(cfg, progs, i))
			return false;

	return true;
}

/*****************************************************************************
 * detach_trace()
 *****************************************************************************/
static void detach_trace(struct capture_programs *progs, unsigned int idx)
{
	if (idx >= progs->nr_of_progs || progs->nr_of_progs == 0 ||
	    !progs->progs[idx].attached)
		return;

	bpf_link__destroy(progs->progs[idx].fentry_link);
	bpf_link__destroy(progs->progs[idx].fexit_link);
	bpf_object__close(progs->progs[idx].prog_obj);
	progs->progs[idx].attached = false;
}

/*****************************************************************************
 * detach_traces()
 *****************************************************************************/
static void detach_traces(struct capture_programs *progs)
{
	for (unsigned int i = 0; i < progs->nr_of_progs; i++)
		detach_trace(progs, i);
}

/*****************************************************************************
 * load_xdp_trace_program()
 *****************************************************************************/
static bool load_xdp_trace_program(struct dumpopt *cfg,
				   struct capture_programs *progs)
{
	DECLARE_LIBXDP_OPTS(xdp_program_opts, opts, 0);
	int                         fd, rc;
	char                        errmsg[STRERR_BUFSIZE];
	struct xdp_program         *prog;
	struct bpf_map             *perf_map;
	struct bpf_map             *data_map;
	struct trace_configuration  trace_cfg;

	if (!cfg || !progs)
		return false;

	silence_libbpf_logging();
	silence_libxdp_logging();

	opts.find_filename = "xdpdump_xdp.o";
	opts.prog_name = "xdpdump";

	prog = xdp_program__create(&opts);
	if (libxdp_get_error(prog)) {
		int err = libxdp_get_error(prog);

		libxdp_strerror(err, errmsg, sizeof(errmsg));
		pr_warn("ERROR: Can't open XDP trace program: %s(%d)\n",
			errmsg, err);
		return false;
	}

	perf_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog),
						"xdpdump_perf_map");
	if (!perf_map) {
		pr_warn("ERROR: Can't find xdpdump_perf_map in the xdp program!\n");
		goto error_exit;
	}

	/* Set the trace configuration in the DATA map */
	data_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog),
						"xdpdump_.data");
	if (!data_map) {
		pr_warn("ERROR: Can't find the .data MAP in the xdp program!\n");
		goto error_exit;
	}

	if (bpf_map__value_size(data_map) != sizeof(trace_cfg)) {
		pr_warn("ERROR: Can't find the correct sized .data MAP in the xdp program!\n");
		goto error_exit;
	}

	trace_cfg.capture_if_ifindex = cfg->iface.ifindex;
	trace_cfg.capture_snaplen = cfg->snaplen;
	trace_cfg.capture_prog_index = 0;
	if (bpf_map__set_initial_value(data_map, &trace_cfg,
				       sizeof(trace_cfg))) {
		pr_warn("ERROR: Can't set initial .data MAP in the xdp program!\n");
		goto error_exit;
	}

	do {
		rc = xdp_program__attach(prog, cfg->iface.ifindex,
					 cfg->load_xdp_mode, 0);

	} while (rc == -EPERM && !double_rlimit());

	if (rc) {
		libxdp_strerror(rc, errmsg, sizeof(errmsg));
		pr_warn("ERROR: Can't attach XDP trace program: %s(%d)\n",
			errmsg, rc);
		goto error_exit;
	}

	fd = bpf_map__fd(perf_map);
	if (fd < 0) {
		pr_warn("ERROR: Can't get xdpdump_perf_map file descriptor: %s\n",
			strerror(errno));

		xdp_program__detach(prog, cfg->iface.ifindex,
				    cfg->load_xdp_mode, 0);
		goto error_exit;
	}

	progs->progs[0].prog = prog;
	progs->progs[0].func = xdp_program__name(prog);
	progs->progs[0].rx_capture = RX_FLAG_FENTRY;
	progs->progs[0].perf_map_fd = fd;
	progs->nr_of_progs = 1;

	return true;

error_exit:
	xdp_program__close(prog);
	return false;
}

/*****************************************************************************
 * unload_xdp_trace_program()
 *****************************************************************************/
static void unload_xdp_trace_program(struct dumpopt *cfg,
				     struct capture_programs *progs)
{
	if (!progs || progs->nr_of_progs != 1)
		return;

	xdp_program__detach(progs->progs[0].prog, cfg->iface.ifindex,
			    cfg->load_xdp_mode, 0);
	xdp_program__close(progs->progs[0].prog);

	progs->progs[0].prog = NULL;
	progs->nr_of_progs = 0;
}

/*****************************************************************************
 * capture_on_interface()
 *****************************************************************************/
static bool capture_on_interface(struct dumpopt *cfg)
{
	int                          err, cnt;
	bool                         rc = false;
	bool                         load_xdp = false;
	bool                         promiscuous = false;
	pcap_t                      *pcap = NULL;
	pcap_dumper_t               *pcap_dumper = NULL;
	struct xpcapng_dumper       *pcapng_dumper = NULL;
	struct perf_buffer          *perf_buf = NULL;
	struct perf_event_attr       perf_attr = {
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.sample_period = 1,
		.wakeup_events = 1,
	};
	struct perf_handler_ctx      perf_ctx;
	struct xdp_multiprog         *mp;
	struct capture_programs      tgt_progs = {};

	mp = xdp_multiprog__get_from_ifindex(cfg->iface.ifindex);
	if (IS_ERR_OR_NULL(mp) || xdp_multiprog__main_prog(mp) == NULL) {

		if (!cfg->load_xdp) {
			pr_warn("WARNING: Specified interface does not have an XDP program loaded%s,"
				"\n         capturing in legacy mode!\n",
				IS_ERR_OR_NULL(mp) ? "" : " in software");

			xdp_multiprog__close(mp);
			return capture_on_legacy_interface(cfg);
		}
		pr_warn("WARNING: Specified interface does not have an XDP program loaded%s!\n"
			"         Will load a capture only XDP program!\n",
			IS_ERR_OR_NULL(mp) ? "" : " in software");
		load_xdp = true;
	}

	if (!load_xdp) {
		if (find_target(cfg, mp, &tgt_progs))
			goto error_exit;

		if (tgt_progs.nr_of_progs == 0) {
			pr_warn("ERROR: Failed finding any attached XDP program!\n");
			goto error_exit;
		}
	}

	/* Enable promiscuous mode if requested. */
	if (cfg->promiscuous) {
		err = set_if_promiscuous_mode(&cfg->iface, true,
					      &cfg->promiscuous);
		if (err) {
			pr_warn("ERROR: Failed setting promiscuous mode: %s(%d)\n",
				strerror(-err), -err);
			goto error_exit;
		}
		promiscuous = true;
	}

	/* Load and attach programs */
	if (!load_xdp) {
		if (!load_and_attach_traces(cfg, &tgt_progs)) {
			/* Actual errors are reported in the above function. */
			goto error_exit;
		}
	} else {
		if (!load_xdp_trace_program(cfg, &tgt_progs)) {
			/* Actual errors are reported in the above function. */
			goto error_exit;
		}
	}

        /* Open the pcap handle */
	if (cfg->pcap_file) {

		if (cfg->use_pcap) {
			pcap = pcap_open_dead(DLT_EN10MB, cfg->snaplen);
			if (!pcap) {
				pr_warn("ERROR: Can't open pcap dead handler!\n");
				goto error_exit;
			}

			pcap_dumper = pcap_dump_open(pcap, cfg->pcap_file);
			if (!pcap_dumper) {
				pr_warn("ERROR: Can't open pcap file for writing!\n");
				goto error_exit;
			}
		} else {
			char           *program_info;
			struct utsname  utinfo;
			char            os_info[260];

			memset(&utinfo, 0, sizeof(utinfo));
			uname(&utinfo);

			os_info[0] = 0;
			if (try_snprintf(os_info, sizeof(os_info), "%s %s %s %s",
					 utinfo.sysname, utinfo.nodename,
					 utinfo.release, utinfo.version)) {
				pr_warn("ERROR: Could not format OS information!\n");
				goto error_exit;
			}

			program_info = get_loaded_program_info(cfg);
			if (!program_info) {
				pr_warn("ERROR: Could not format program information!\n");
				goto error_exit;
			}

			pcapng_dumper = xpcapng_dump_open(cfg->pcap_file,
							  program_info,
							  utinfo.machine,
							  os_info,
							  "xdpdump v" TOOLS_VERSION);

			free(program_info);
			if (!pcapng_dumper) {
				pr_warn("ERROR: Can't open PcapNG file for writing!\n");
				goto error_exit;
			}


			if (!add_interfaces_to_pcapng(cfg, pcapng_dumper,
						     &tgt_progs)) {
				/* Error output is handled in
				 * add_interfaces_to_pcapng()
				 */
				goto error_exit;
			}
		}
	}

	/* No more error conditions, display some capture information */
	fprintf(stderr, "listening on %s, ingress XDP program ",
		cfg->iface.ifname);

	for (unsigned int i = 0; i < tgt_progs.nr_of_progs; i++)
		fprintf(stderr, "ID %u func %s, ",
			xdp_program__id(tgt_progs.progs[i].prog),
			tgt_progs.progs[i].func);

	fprintf(stderr, "capture mode %s, capture size %d bytes\n",
		get_capture_mode_string(tgt_progs.progs[0].rx_capture),
		cfg->snaplen);

	/* Setup perf context */
	memset(&perf_ctx, 0, sizeof(perf_ctx));
	perf_ctx.cfg = cfg;
	perf_ctx.xdp_progs = &tgt_progs;
	perf_ctx.pcap = pcap;
	perf_ctx.pcap_dumper = pcap_dumper;
	perf_ctx.pcapng_dumper = pcapng_dumper;

	if (get_epoch_to_uptime_delta(&perf_ctx.epoch_delta))
		goto error_exit;

	/* Determine the perf wakeup_events value to use */
#ifdef HAVE_LIBBPF_PERF_BUFFER__CONSUME
	if (cfg->pcap_file) {
		if (cfg->pcap_file[0] == '-' && cfg->pcap_file[1] == 0) {
			/* If we pipe trough stdio we do not want to buffer
			 * any packets in the perf ring.
			 */
			perf_attr.wakeup_events = 1;
		} else {
			/*
			 * If no specific wakeup value is specified assume
			 * an average packet size of 2K we would like to
			 * fill without losing any packets.
			 */
			uint32_t events = PERF_MMAP_PAGE_COUNT * getpagesize() /
				(libbpf_num_possible_cpus() ?: 1) / 2048;

			if (events > 0)
				perf_attr.wakeup_events = min(PERF_MAX_WAKEUP_EVENTS,
							      events);
		}
	} else {
		/* Only buffer in perf ring when using pcap_file */
		perf_attr.wakeup_events = 1;
	}
	/* Cmdline option --perf-wakeup can override buffering levels */
	if (cfg->perf_wakeup)
		perf_attr.wakeup_events = cfg->perf_wakeup;
#endif
	pr_debug("perf-wakeup value uses is %u\n", perf_attr.wakeup_events);

#ifdef HAVE_LIBBPF_PERF_BUFFER__NEW_RAW
	/* the configure check looks for the 6-argument variant of the function */
	perf_buf = perf_buffer__new_raw(tgt_progs.progs[0].perf_map_fd,
					PERF_MMAP_PAGE_COUNT,
					&perf_attr, handle_perf_event,
					&perf_ctx, NULL);
#else
	struct perf_buffer_raw_opts  perf_opts = {};

	/* Setup perf ring buffers */
	perf_opts.attr = &perf_attr;
	perf_opts.event_cb = handle_perf_event;
	perf_opts.ctx = &perf_ctx;
	perf_buf = perf_buffer__new_raw(tgt_progs.progs[0].perf_map_fd,
					PERF_MMAP_PAGE_COUNT,
					&perf_opts);
#endif

	if (perf_buf == NULL) {
		pr_warn("ERROR: Failed to allocate raw perf buffer: %s(%d)",
			strerror(errno), errno);
		goto error_exit;
	}

	/* Loop trough the dumper */
	while (!exit_xdpdump) {
		cnt = perf_buffer__poll(perf_buf, 1000);
		if (cnt < 0 && errno != EINTR) {
			pr_warn("ERROR: Perf buffer polling failed: %s(%d)",
				strerror(errno), errno);
			goto error_exit;
		}
	}
#ifdef HAVE_LIBBPF_PERF_BUFFER__CONSUME
	perf_buffer__consume(perf_buf);
#endif

	fprintf(stderr, "\n%"PRIu64" packets captured\n",
		perf_ctx.captured_packets);
	fprintf(stderr, "%"PRIu64" packets dropped by perf ring\n",
		perf_ctx.missed_events);


	rc = true;

error_exit:
	/* Cleanup all our resources */
	if (promiscuous && cfg->promiscuous) {
		err = set_if_promiscuous_mode(&cfg->iface, false, NULL);
		if (err)
			pr_warn("ERROR: Failed disabling promiscuous mode: "
				"%s(%d)\n", strerror(-err), -err);
	}

	perf_buffer__free(perf_buf);
	xpcapng_dump_close(pcapng_dumper);

	if (pcap_dumper)
		pcap_dump_close(pcap_dumper);

	if (pcap)
		pcap_close(pcap);

	if (load_xdp)
		unload_xdp_trace_program(cfg, &tgt_progs);
	else
		detach_traces(&tgt_progs);

	xdp_multiprog__close(mp);
	return rc;
}

/*****************************************************************************
 * signal_handler()
 *****************************************************************************/
static void signal_handler(__unused int signo)
{
	exit_xdpdump = true;
	if (exit_pcap)
		pcap_breakloop(exit_pcap);
}

/*****************************************************************************
 * main()
 *****************************************************************************/
int main(int argc, char **argv)
{
	if (parse_cmdline_args(argc, argv, xdpdump_options,
			       &cfg_dumpopt, sizeof(cfg_dumpopt),
			       PROG_NAME, PROG_NAME,
			       "XDPDump tool to dump network traffic",
			       &defaults_dumpopt) != 0)
		return EXIT_FAILURE;

	/* If all the options are parsed ok, make sure we are root! */
	if (check_bpf_environ())
		return EXIT_FAILURE;

	if (cfg_dumpopt.snaplen == 0)
		cfg_dumpopt.snaplen = DEFAULT_SNAP_LEN;

	if (cfg_dumpopt.rx_capture == 0)
		cfg_dumpopt.rx_capture = RX_FLAG_FENTRY;

	/* See if we need to dump interfaces and exit */
	if (cfg_dumpopt.list_interfaces) {
		if (iface_print_status(NULL))
			return EXIT_SUCCESS;
		return EXIT_FAILURE;
	}

	/* Check if the system does not have more cores than we assume. */
	if (sysconf(_SC_NPROCESSORS_CONF) > MAX_CPUS) {
		pr_warn("ERROR: System has more cores (%ld) than maximum "
			"supported (%d)!\n", sysconf(_SC_NPROCESSORS_CONF),
			MAX_CPUS);
		return EXIT_FAILURE;
	}

	/* From here on we assume we need to capture data on an interface */
	if (signal(SIGINT, signal_handler) == SIG_ERR ||
	    signal(SIGHUP, signal_handler) == SIG_ERR ||
	    signal(SIGTERM, signal_handler) == SIG_ERR) {
		pr_warn("ERROR: Failed assigning signal handler: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	if (cfg_dumpopt.iface.ifname == NULL) {
		pr_warn("ERROR: You must specific an interface to capture on!\n");
		return EXIT_FAILURE;
	}

	if (!capture_on_interface(&cfg_dumpopt))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
