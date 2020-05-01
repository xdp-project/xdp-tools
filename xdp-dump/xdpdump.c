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
#include <bpf/libbpf.h>

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

#include "logging.h"
#include "params.h"
#include "util.h"
#include "xdpdump.h"
#include "xpcapng.h"

/*****************************************************************************
 * Local definitions and global variables
 *****************************************************************************/
#define PROG_NAME "xdpdump"
#define DEFAULT_SNAP_LEN 262144

#define RX_FLAG_FENTRY (1<<0)
#define RX_FLAG_FEXIT  (1<<1)

struct flag_val rx_capture_flags[] = {
	{"entry", RX_FLAG_FENTRY},
	{"exit", RX_FLAG_FEXIT},
	{}
};

static const struct dumpopt {
	bool                  list_interfaces;
	bool                  hex_dump;
	bool                  use_pcap;
	bool                  version;
	struct iface          iface;
	uint32_t              snaplen;
	char                 *pcap_file;
	unsigned int          rx_capture;
} defaults_dumpopt = {
	.list_interfaces = false,
	.hex_dump = false,
	.use_pcap = false,
	.version = false,
	.snaplen = DEFAULT_SNAP_LEN,
	.rx_capture = RX_FLAG_FENTRY,
};
struct dumpopt cfg_dumpopt;

static struct prog_option xdpdump_options[] = {
	DEFINE_OPTION("rx-capture", OPT_FLAGS, struct dumpopt, rx_capture,
		      .short_opt = 1,
		      .metavar = "<mode>",
		      .typearg = rx_capture_flags,
		      .help = "Capture point for the rx direction"),
	DEFINE_OPTION("list-interfaces", OPT_BOOL, struct dumpopt,
		      list_interfaces,
		      .short_opt = 'D',
		      .help = "Print the list of available interfaces"),
	DEFINE_OPTION("interface", OPT_IFNAME, struct dumpopt, iface,
		      .short_opt = 'i',
		      .metavar = "<ifname>",
		      .help = "Name of interface to capture on"),
	DEFINE_OPTION("snapshot-length", OPT_U32, struct dumpopt, snaplen,
		      .short_opt = 's',
		      .metavar = "<snaplen>",
		      .help = "Minimum bytes of packet to capture"),
	DEFINE_OPTION("use-pcap", OPT_BOOL, struct dumpopt, use_pcap,
		      .short_opt = 2,
		      .help = "Use legacy pcap format for XDP traces"),
	DEFINE_OPTION("version", OPT_BOOL, struct dumpopt, version,
		      .short_opt = 3,
		      .help = "Print version information and exit"),
	DEFINE_OPTION("write", OPT_STRING, struct dumpopt, pcap_file,
		      .short_opt = 'w',
		      .metavar = "<file>",
		      .help = "Write raw packets to pcap file"),
	DEFINE_OPTION("hex", OPT_BOOL, struct dumpopt, hex_dump,
		      .short_opt = 'x',
		      .help = "Print the full packet in hex"),
	END_OPTIONS
};

struct perf_handler_ctx {
	uint64_t               missed_events;
	uint64_t               last_missed_events;
	uint64_t               captured_packets;
	uint64_t               epoch_delta;
	uint64_t               packet_id;
	uint64_t               cpu_packet_id[MAX_CPUS];
	struct dumpopt        *cfg;
	pcap_t                *pcap;
	pcap_dumper_t         *pcap_dumper;
	struct xpcapng_dumper *pcapng_dumper;
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
		return 0;

	if (ereq.req.link_mode_masks_nwords >= 0 ||
	    ereq.req.link_mode_masks_nwords < -MAX_MODE_MASKS ||
	    ereq.req.cmd != ETHTOOL_GLINKSETTINGS)
		return 0;

	/* Now ask for the data set, and extract the speed in bps. */
	ereq.req.link_mode_masks_nwords = -ereq.req.link_mode_masks_nwords;
	if (ioctl(fd, SIOCETHTOOL, &ifr) != 0)
		return 0;

	/* If speed is unknown return 0. */
	if (ereq.req.speed == -1)
		ereq.req.speed = 0;

	close(fd);
	return ereq.req.speed * 1000000;
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

	snprintf(buffer, len,
		 "driver: \"%s\", version: \"%s\", "
		 "fw-version: \"%s\", rom-version: \"%s\", "
		 "bus-info: \"%s\"",
		 info.driver, info.version, info.fw_version,
		 info.erom_version, info.bus_info);
	r_buffer = buffer;
exit:
	close(fd);
	return r_buffer;
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
	int zero_offset;

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
	bool                      fexit;
	uint64_t                  ts;
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
		    e->size < (sizeof(struct pkt_trace_metadata) + e->metadata.cap_len))
			return LIBBPF_PERF_EVENT_CONT;

		fexit = e->metadata.flags & MDF_DIRECTION_FEXIT;
		if (!fexit)
			ctx->cpu_packet_id[cpu] = ++ctx->packet_id;

		ts = e->time + ctx->epoch_delta;
		if (ctx->pcap_dumper) {
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

		} else if (ctx->pcapng_dumper) {
			char     meta[80];
			int64_t  action = e->metadata.action;
			uint32_t queue = e->metadata.rx_queue;
			uint64_t pktid = ctx->cpu_packet_id[cpu];

			/* For now we keep the id/queue/action information in
			 * the packet comment until tools like WireShark
			 * support the specific EPB options
			 */
			if (fexit)
				snprintf(meta, sizeof(meta),
					 "id: %"PRIu64", queue: %u, "
					 "action: %"PRId64"%s",
					 pktid, queue, action,
					 get_xdp_action_string(action));
			else
				snprintf(meta, sizeof(meta),
					 "id: %"PRIu64", queue: %u",
					 pktid, queue);

			xpcapng_dump_enhanced_pkt(ctx->pcapng_dumper,
						  fexit ? 1 : 0,
						  PCAPNG_EPB_FLAG_INBOUND,
						  ts, e->metadata.pkt_len,
						  min(e->metadata.cap_len,
						      ctx->cfg->snaplen),
						  e->packet,
						  ctx->last_missed_events,
						  meta, &pktid, &queue,
						  fexit ? &action : NULL);

			ctx->last_missed_events = 0;
			if (ctx->cfg->pcap_file[0] == '-' &&
			    ctx->cfg->pcap_file[1] == 0)
				xpcapng_dump_flush(ctx->pcapng_dumper);
		} else {
			int  i;
			char hline[SNPRINTH_MIN_BUFFER_SIZE];

			if (ctx->cfg->hex_dump) {
				printf("%llu.%09lld: @%s%s: packet size %u "
				       "bytes, captured %u bytes on if_index "
				       "%u, rx queue %u, id %"PRIu64"\n",
				       ts / 1000000000ULL,
				       ts % 1000000000ULL,
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
				printf("%llu.%09lld: @%s%s: packet size %u "
				       "bytes on if_index %u, rx queue %u, "
				       "id %"PRIu64"\n",
				       ts / 1000000000ULL,
				       ts % 1000000000ULL,
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
static uint64_t get_epoch_to_uptime_delta(void)
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

	clock_gettime(CLOCK_MONOTONIC, &ts);
	uptime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	return epoch - uptime;
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
			      true, 1000, errbuf);
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
			int i;
			char hline[SNPRINTH_MIN_BUFFER_SIZE];

			if (cfg->hex_dump) {
				printf("%lu.%06lu: packet size %u bytes, "
				       "captured %u bytes on if_name \"%s\"\n",
				       h.ts.tv_sec, h.ts.tv_usec,
				       h.len, h.caplen, cfg->iface.ifname);

				for (i = 0; i < h.caplen; i += 16) {
					snprinth(hline, sizeof(hline),
						 packet, h.caplen, i);
					printf("  %s\n", hline);
				}
			} else {
				printf("%lu.%06lu: packet size %u bytes on "
				       "if_name \"%s\"\n",
				       h.ts.tv_sec, h.ts.tv_usec,
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
 * capture_on_interface()
 *****************************************************************************/
static bool capture_on_interface(struct dumpopt *cfg)
{
	enum xdp_attach_mode         mode;
	int                          err;
	int                          perf_map_fd;
	int                          prog_fd;
	int                          rc = false;
	pcap_t                      *pcap = NULL;
	pcap_dumper_t               *pcap_dumper = NULL;
	struct xpcapng_dumper       *pcapng_dumper = NULL;
	struct bpf_link             *trace_link_fentry = NULL;
	struct bpf_link             *trace_link_fexit = NULL;
	struct bpf_map              *perf_map;
	struct bpf_object           *trace_obj = NULL;
	struct bpf_prog_info         info = {};
	struct bpf_program          *trace_prog_fentry;
	struct bpf_program          *trace_prog_fexit;
	struct perf_buffer          *perf_buf;
	struct perf_buffer_raw_opts  perf_opts = {};
	struct perf_event_attr       perf_attr = {
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.sample_period = 1,
		.wakeup_events = 1,
	};
	struct perf_handler_ctx      perf_ctx;

	if (get_loaded_program(&cfg->iface, &mode, &info) != 0) {
		pr_warn("WARNING: Specified interface does not have an XDP "
			"program loaded, capturing\n         in legacy mode!\n");
		return capture_on_legacy_interface(cfg);
	}

	prog_fd = bpf_prog_get_fd_by_id(info.id);
	if (prog_fd < 0) {
		pr_warn("ERROR: Can't get XDP program id %u's file descriptor: %s\n",
			info.id, strerror(errno));
		return false;
	}

	silence_libbpf_logging();

rlimit_loop:
	/* Load the trace program object */
	trace_obj = open_bpf_file("xdpdump_bpf.o", NULL);
	err = libbpf_get_error(trace_obj);
	if (err) {
		pr_warn("ERROR: Can't open XDP trace program: %s(%d)\n",
			strerror(err), err);
		goto error_exit;
	}

	/* Locate the fentry and fexit functions */
	trace_prog_fentry = bpf_object__find_program_by_title(trace_obj,
							      "fentry/func");
	if (!trace_prog_fentry) {
		pr_warn("ERROR: Can't find XDP trace fentry function!\n");
		goto error_exit;
	}

	trace_prog_fexit = bpf_object__find_program_by_title(trace_obj,
							     "fexit/func");
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
	bpf_program__set_attach_target(trace_prog_fentry, prog_fd, info.name);
	bpf_program__set_attach_target(trace_prog_fexit, prog_fd, info.name);

	/* Load the bpf object into memory */
	err = bpf_object__load(trace_obj);
	if (err) {
		char err_msg[STRERR_BUFSIZE];

		if (err == -EPERM) {
			pr_debug("Permission denied when loading eBPF object; "
				 "raising rlimit and retrying\n");

			if (!double_rlimit()) {
				bpf_object__close(trace_obj);
				goto rlimit_loop;
			}
		}

		libbpf_strerror(err, err_msg, sizeof(err_msg));
		pr_warn("ERROR: Can't load eBPF object: %s(%d)\n",
			err_msg, err);
		goto error_exit;
	}

	/* Attach trace programs only in the direction(s) needed */
	if (cfg->rx_capture & RX_FLAG_FENTRY) {
		trace_link_fentry = bpf_program__attach_trace(trace_prog_fentry);
		err = libbpf_get_error(trace_link_fentry);
		if (err) {
			pr_warn("ERROR: Can't attach XDP trace fentry function: %s\n",
				strerror(-err));
			goto error_exit;
		}
	}

	if (cfg->rx_capture & RX_FLAG_FEXIT) {
		trace_link_fexit = bpf_program__attach_trace(trace_prog_fexit);
		err = libbpf_get_error(trace_link_fexit);
		if (err) {
			pr_warn("ERROR: Can't attach XDP trace fexit function: %s\n",
				strerror(-err));
			goto error_exit;
		}
	}

	/* Figure out the fd for the BPF_MAP_TYPE_PERF_EVENT_ARRAY trace map */
	perf_map = bpf_object__find_map_by_name(trace_obj, "xdpdump_perf_map");
	if (!perf_map) {
		pr_warn("ERROR: Can't find xdpdump_perf_map in trace program!\n");
		goto error_exit;
	}
	perf_map_fd = bpf_map__fd(perf_map);
	if (perf_map_fd < 0) {
		pr_warn("ERROR: Can't get xdpdump_perf_map file descriptor: %s\n",
			strerror(errno));
		return false;
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
			char           if_name[IFNAMSIZ + 7];
			char           if_descr[BPF_OBJ_NAME_LEN + IFNAMSIZ + 10];
			char           if_drv[260];
			uint64_t       if_speed;
			struct utsname utinfo;

			memset(&utinfo, 0, sizeof(utinfo));
			uname(&utinfo);

			snprintf(if_drv, sizeof(if_drv), "%s %s %s %s",
				 utinfo.sysname, utinfo.nodename,
				 utinfo.release, utinfo.version);
			pcapng_dumper = xpcapng_dump_open(cfg->pcap_file,
							  NULL, utinfo.machine,
							  if_drv,
							  "xdpdump v" XDPDUMP_VERSION);
			if (!pcapng_dumper) {
				pr_warn("ERROR: Can't open PcapNG file for writing!\n");
				goto error_exit;
			}

			if_speed = get_if_speed(&cfg->iface);
			if_drv[0] = 0;
			get_if_drv_info(&cfg->iface, if_drv, sizeof(if_drv));

			snprintf(if_name, sizeof(if_name), "%s@fentry",
				 cfg->iface.ifname);
			snprintf(if_descr, sizeof(if_descr), "%s:%s()@fentry",
				 cfg->iface.ifname, info.name);
			if (xpcapng_dump_add_interface(pcapng_dumper,
						       cfg->snaplen,
						       if_name, if_descr, NULL,
						       if_speed,
						       9 /* nsec resolution */,
						       if_drv) != 0) {
				pr_warn("ERROR: Can't add entry interfaced to PcapNG file!\n");
				goto error_exit;
			}

			snprintf(if_name, sizeof(if_name), "%s@fexit",
				 cfg->iface.ifname);
			snprintf(if_descr, sizeof(if_descr), "%s:%s()@fexit",
				 cfg->iface.ifname, info.name);
			if (xpcapng_dump_add_interface(pcapng_dumper,
						       cfg->snaplen,
						       if_name, if_descr, NULL,
						       if_speed,
						       9 /* nsec resolution */,
						       if_drv) != 1) {
				pr_warn("ERROR: Can't add exit interfaced to PcapNG file!\n");
				goto error_exit;
			}
		}
	}

	/* Setup perf context */
	memset(&perf_ctx, 0, sizeof(perf_ctx));
	perf_ctx.cfg = cfg;
	perf_ctx.pcap = pcap;
	perf_ctx.pcap_dumper = pcap_dumper;
	perf_ctx.pcapng_dumper = pcapng_dumper;
	perf_ctx.epoch_delta = get_epoch_to_uptime_delta();

	/* Setup perf ring buffers */
	perf_opts.attr = &perf_attr;
	perf_opts.event_cb = handle_perf_event;
	perf_opts.ctx = &perf_ctx;
	perf_buf = perf_buffer__new_raw(perf_map_fd, PERF_MMAP_PAGE_COUNT,
					&perf_opts);

	/* Loop trough the dumper */
	while (!exit_xdpdump) {
		err = perf_buffer__poll(perf_buf, 1000);
		if (err < 0 && err != -EINTR) {
			pr_warn("ERROR: Perf buffer polling failed: %s(%d)",
				strerror(err), err);
			goto error_exit;
		}
	}

	fprintf(stderr, "\n%"PRIu64" packets captured\n",
		perf_ctx.captured_packets);
	fprintf(stderr, "%"PRIu64" packets dropped by perf ring\n",
		perf_ctx.missed_events);

	rc = true;

error_exit:
	/* Cleanup all our resources */
	if (pcapng_dumper)
		xpcapng_dump_close(pcapng_dumper);

	if (pcap_dumper)
		pcap_dump_close(pcap_dumper);

	if (pcap)
		pcap_close(pcap);

	if (trace_link_fentry)
		bpf_link__destroy(trace_link_fentry);

	if (trace_link_fexit)
		bpf_link__destroy(trace_link_fexit);

	if (trace_obj)
		bpf_object__close(trace_obj);

	return rc;
}

/*****************************************************************************
 * list_interfaces()
 *****************************************************************************/
static bool list_interfaces(struct dumpopt *cfg)
{
	struct if_nameindex *idx, *indexes;

	indexes = if_nameindex();
	if (!indexes) {
		pr_warn("Couldn't get list of interfaces: %s\n",
			strerror(errno));
		return false;
	}

	printf("%-8.8s  %-16.16s  %s\n", "if_index", "if_name",
	       "XDP program entry function");
	printf("--------  ----------------  "
	       "--------------------------------------------------\n");
	for (idx = indexes; idx->if_index; idx++) {
		enum xdp_attach_mode mode;
		struct bpf_prog_info info = {};
		struct iface iface = {
			.ifindex = idx->if_index,
			.ifname = idx->if_name,
		};

		if (get_loaded_program(&iface, &mode, &info) != 0) {
			printf("%-8d  %-16.16s  %s\n",
			       iface.ifindex, iface.ifname,
			       "<No XDP program loaded!>");
		} else {
			printf("%-8d  %-16.16s  %s()\n",
			       iface.ifindex, iface.ifname,
			       info.name);
		}
	}
	if_freenameindex(indexes);
	return true;
}

/*****************************************************************************
 * signal_handler()
 *****************************************************************************/
static void signal_handler(int signo)
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
	if (parse_cmdline_args(argc, argv, xdpdump_options, &cfg_dumpopt,
			       PROG_NAME,
			       "XDPDump tool to dump network traffic",
			       &defaults_dumpopt) != 0)
		return EXIT_FAILURE;

	/* Do we need to dump version information? */
	if (cfg_dumpopt.version) {
		printf("xdpdump version " XDPDUMP_VERSION "\n");
		return EXIT_SUCCESS;
	}

	/* If all the options are parsed ok, make sure we are root! */
	if (check_bpf_environ(""))
		return EXIT_FAILURE;

	if (cfg_dumpopt.snaplen == 0)
		cfg_dumpopt.snaplen = DEFAULT_SNAP_LEN;

	if (cfg_dumpopt.rx_capture == 0)
		cfg_dumpopt.rx_capture = RX_FLAG_FENTRY;

	/* See if we need to dump interfaces and exit */
	if (cfg_dumpopt.list_interfaces) {
		if (list_interfaces(&cfg_dumpopt))
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
	if (signal(SIGINT, signal_handler) || signal(SIGHUP, signal_handler) ||
	    signal(SIGTERM, signal_handler)) {
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
