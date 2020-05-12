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

#include <linux/perf_event.h>
#include <linux/err.h>

#include <net/if.h>

#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/dlt.h>
#include <pcap/pcap.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>

#include "params.h"
#include "logging.h"
#include "util.h"
#include "xdpdump.h"

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
	struct iface          iface;
	uint32_t              snaplen;
	char                 *pcap_file;
	char                 *program_names;
	unsigned int          rx_capture;
} defaults_dumpopt = {
	.list_interfaces = false,
	.snaplen = DEFAULT_SNAP_LEN,
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
	DEFINE_OPTION("interface", OPT_IFNAME, struct dumpopt, iface,
		      .short_opt = 'i',
		      .metavar = "<ifname>",
		      .help = "Name of interface to capture on"),
	DEFINE_OPTION("program-names", OPT_STRING, struct dumpopt,
		      program_names,
		      .short_opt = 'p',
		      .metavar = "<prog>",
		      .help = "Specific program to attach to"),
	DEFINE_OPTION("snapshot-length", OPT_U32, struct dumpopt, snaplen,
		      .short_opt = 's',
		      .metavar = "<snaplen>",
		      .help = "Minimum bytes of packet to capture"),
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
	uint64_t                   missed_events;
	uint64_t                   captured_packets;
	uint64_t                   epoch_delta;
	struct dumpopt            *cfg;
	pcap_t                    *pcap;
	pcap_dumper_t             *pcap_dumper;
};

bool    exit_xdpdump;
pcap_t *exit_pcap;

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
	uint64_t ts;
	struct perf_handler_ctx *ctx = private_data;
	struct perf_sample_event *e = container_of(event,
						   struct perf_sample_event,
						   header);
	struct perf_lost_event *lost = container_of(event,
						    struct perf_lost_event,
						    header);

	switch(e->header.type) {
	case PERF_RECORD_SAMPLE:

		if (e->header.size < sizeof(struct perf_sample_event) ||
		    e->size < (sizeof(struct pkt_trace_metadata) + e->metadata.cap_len))
			return LIBBPF_PERF_EVENT_CONT;

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
		} else {
			int i;
			char hline[SNPRINTH_MIN_BUFFER_SIZE];
			bool fexit = e->metadata.flags & MDF_DIRECTION_FEXIT;


			if (ctx->cfg->hex_dump) {
				printf("%llu.%09lld: @%s%s: packet size %u "
				       "bytes, captured %u bytes on "
				       "if_index %u, rx queue %u\n",
				       ts / 1000000000ULL,
				       ts % 1000000000ULL,
				       fexit ? "exit" : "entry",
				       fexit ? get_xdp_action_string(
					       e->metadata.action) : "",
				       e->metadata.pkt_len,
				       e->metadata.cap_len, e->metadata.ifindex,
				       e->metadata.rx_queue);

				for (i = 0; i < e->metadata.cap_len; i += 16) {
					snprinth(hline, sizeof(hline),
						 e->packet,
						 e->metadata.cap_len, i);
					printf("  %s\n", hline);
				}
			} else {
				printf("%llu.%09lld: @%s%s: packet size %u "
				       "bytes on if_index %u, rx queue %u\n",
				       ts / 1000000000ULL,
				       ts % 1000000000ULL,
				       fexit ? "exit" : "entry",
				       fexit ? get_xdp_action_string(
					       e->metadata.action) : "",
				       e->metadata.pkt_len,e->metadata.ifindex,
				       e->metadata.rx_queue);
			}
		}
		ctx->captured_packets++;
		break;

	case PERF_RECORD_LOST:
		ctx->missed_events += lost->lost;
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
 * find_func_matches()
 *****************************************************************************/
static size_t find_func_matches(const struct btf *btf,
				const char *func_name,
				const char **found_name,
				bool print, bool exact)
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

	nr_types = btf__get_nr_types(btf);
	for (i = 1; i <= nr_types; i++) {
		t = btf__type_by_id(btf, i);
		if (!btf_is_func(t))
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (!strncmp(name, func_name, len)) {
			pr_debug("Found func %s matching %s\n",
				 name, func_name);

			if (print)
				pr_warn("  %s\n", name);

			/* Do an exact match if the user specified a function
			 * name, or if there is no possibility of truncation
			 * because the length is different from the truncated
			 * length.
			 */
			if (strlen(name) == len &&
			    (exact || len != BPF_OBJ_NAME_LEN -1)) {
				*found_name = name;
				return 1; /* exact match */
			}

			/* prefix, may not be unique */
			matches++;
			match = t;
		}
	}

	if (matches == 1)
		*found_name = btf__name_by_offset(btf, match->name_off);

	return matches;
}

/*****************************************************************************
 * find_target()
 *****************************************************************************/
static int find_target(struct xdp_multiprog *mp,
		       char *function_override,
		       struct xdp_program **tgt_prog,
		       const char **tgt_func)
{
	bool match_exact = !!function_override;
	struct xdp_program *prog, *p;
	size_t matches = 0;
	const char *func;

	prog = xdp_multiprog__main_prog(mp);
	matches = find_func_matches(xdp_program__btf(prog),
				    function_override ?: xdp_program__name(prog),
				    &func, false, match_exact);

	if (!function_override)
		goto check;

	for (p = xdp_multiprog__next_prog(NULL, mp);
	     p;
	     p = xdp_multiprog__next_prog(p, mp)) {
		const char *f;
		size_t m;

		m = find_func_matches(xdp_program__btf(p),
				      function_override, &f, false,
				      match_exact);
		if (m == 1) {
			prog = p;
			func = f;
		}
		matches += m;
	}

check:
	if (!matches) {
		pr_warn("ERROR: Can't find function '%s' on interface!\n",
			function_override);
		return -ENOENT;
	} else if (matches == 1) {
		*tgt_prog = prog;
		*tgt_func = func;
		return 0;
	}

	pr_warn("ERROR: Can't identify the full XDP main function!\n"
		"The following is a list of candidates:\n");

	prog = xdp_multiprog__main_prog(mp);
	find_func_matches(xdp_program__btf(prog),
			  function_override ?: xdp_program__name(prog),
			  &func, true, match_exact);

	for (p = xdp_multiprog__next_prog(NULL, mp);
	     p && function_override;
	     p = xdp_multiprog__next_prog(p, mp))

		find_func_matches(xdp_program__btf(p),
				  function_override, &func, true, match_exact);

	pr_warn("Please use the -p option to pick the correct one.\n");
	return -EAGAIN;
}

/*****************************************************************************
 * capture_on_interface()
 *****************************************************************************/
static bool capture_on_interface(struct dumpopt *cfg)
{
	int                          err;
	int                          perf_map_fd;
	bool                         rc = false;
	pcap_t                      *pcap = NULL;
	pcap_dumper_t               *pcap_dumper = NULL;
	struct bpf_link             *trace_link_fentry = NULL;
	struct bpf_link             *trace_link_fexit = NULL;
	struct bpf_map              *perf_map;
	struct bpf_map              *data_map;
	const struct bpf_map_def    *data_map_def;
	struct bpf_object           *trace_obj = NULL;
	struct bpf_program          *trace_prog_fentry;
	struct bpf_program          *trace_prog_fexit;
	struct trace_configuration   trace_cfg;
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
	struct xdp_multiprog         *mp;
	struct xdp_program           *tgt_prog;
	const char                   *tgt_func;

	mp = xdp_multiprog__get_from_ifindex(cfg->iface.ifindex);
	if (IS_ERR_OR_NULL(mp)) {
		pr_warn("WARNING: Specified interface does not have an XDP "
			"program loaded, capturing\n         in legacy mode!\n");
		return capture_on_legacy_interface(cfg);
	}

	if (find_target(mp, cfg->program_names, &tgt_prog, &tgt_func))
		return false;

	silence_libbpf_logging();

rlimit_loop:
	/* Load the trace program object */
	trace_obj = open_bpf_file("xdpdump_bpf.o", NULL);
	err = libbpf_get_error(trace_obj);
	if (err) {
		pr_warn("ERROR: Can't open XDP trace program: %s(%d)\n",
			strerror(err), err);
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

	data_map_def = bpf_map__def(data_map);
	if (!data_map_def ||
	    data_map_def->value_size != sizeof(trace_cfg)) {
		pr_warn("ERROR: Can't find the correct sized .data MAP in the "
			"trace program!\n");
		goto error_exit;
	}

	trace_cfg.capture_if_ifindex = cfg->iface.ifindex;
	trace_cfg.capture_snaplen = cfg->snaplen;
	if (bpf_map__set_initial_value(data_map, &trace_cfg,
				       sizeof(trace_cfg))) {
		pr_warn("ERROR: Can't set initial .data MAP in the trace "
			"program!\n");
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
	bpf_program__set_attach_target(trace_prog_fentry,
				       xdp_program__fd(tgt_prog),
				       tgt_func);
	bpf_program__set_attach_target(trace_prog_fexit,
				       xdp_program__fd(tgt_prog),
				       tgt_func);

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
	}

	/* No more error conditions, display some capture information */
	fprintf(stderr, "listening on %s, ingress XDP program ID %u func %s, "
		"capture mode %s, capture size %d bytes\n",
		cfg->iface.ifname, xdp_program__id(tgt_prog), tgt_func,
		get_capture_mode_string(cfg->rx_capture), cfg->snaplen);

	/* Setup perf context */
	memset(&perf_ctx, 0, sizeof(perf_ctx));
	perf_ctx.cfg = cfg;
	perf_ctx.pcap = pcap;
	perf_ctx.pcap_dumper = pcap_dumper;
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

	if (mp)
		xdp_multiprog__close(mp);

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
		struct xdp_multiprog *mp;

		mp = xdp_multiprog__get_from_ifindex(idx->if_index);
		if (IS_ERR_OR_NULL(mp)) {
			printf("%-8d  %-16.16s  %s\n",
			       idx->if_index, idx->if_name,
			       "<No XDP program loaded!>");
		} else {
			struct xdp_program *prog = NULL;

			printf("%-8d  %-16.16s  %s()\n",
			       idx->if_index, idx->if_name,
			       xdp_program__name(xdp_multiprog__main_prog(mp)));

			while ((prog = xdp_multiprog__next_prog(prog, mp)))
				printf("%-29s %s()\n", "=>",
				       xdp_program__name(prog));

			xdp_multiprog__close(mp);
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
