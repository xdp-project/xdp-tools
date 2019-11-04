/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include "stats.h"
#include "util.h"
#include "logging.h"

#include "bpf.h"
#include "libbpf.h"

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print_header()
{
	/* Print stats "header" */
	printf("%-12s\n", "XDP-action");
}

void stats_print_one(struct stats_record *stats_rec)
{
	struct record *rec;
	__u64 packets, bytes;
	int i;

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt = "  %-35s %'11lld pkts %'11lld Kbytes\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		packets = rec->total.rx_packets;
		bytes   = rec->total.rx_bytes;

		if (packets)
			printf(fmt, action, rec->total.rx_packets,
			       rec->total.rx_bytes / 1000);
	}
}

void stats_print(struct stats_record *stats_rec,
		 struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i;

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt_per = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		char *fmt_once = "%-12s %'11lld pkts"
			" %'11lld Kbytes\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		packets = rec->total.rx_packets;
		bytes   = rec->total.rx_bytes;

		if (!stats_prev) {
			if (packets)
				printf(fmt_once, action, rec->total.rx_packets,
				       rec->total.rx_bytes / 1000);
			continue;
		}

		prev = &stats_prev->stats[i];
		packets -= prev->total.rx_packets;
		bytes -= prev->total.rx_bytes;

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		pps     = packets / period;

		bps     = (bytes * 8)/ period / 1000000;

		printf(fmt_per, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1000 , bps,
		       period);
	}
	printf("\n");
}


/* BPF_MAP_TYPE_ARRAY */
static int map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	int err = 0;

	bpf_map_lookup_elem(fd, &key, value);
	if (err)
		pr_debug("bpf_map_lookup_elem failed key:0x%X\n", key);

	return err;
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
static int map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i, err;

	err = bpf_map_lookup_elem(fd, &key, values);
	if (err) {
		pr_debug("bpf_map_lookup_elem failed key:0x%X\n", key);
		return err;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
	return 0;
}

static int map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;
	int err;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		err = map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		err = map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		pr_warn("Unknown map_type: %u cannot handle\n", map_type);
		err = -EINVAL;
		break;
	}

	if (err)
		return err;

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return 0;
}

int stats_collect(int map_fd, __u32 map_type,
		  struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;
	int err;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		err = map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
		if (err)
			return err;
	}

	return 0;
}

int stats_poll(const char *pin_dir, const char *map_name, int interval)
{
	struct bpf_map_info info = {};
	struct stats_record prev, record = { 0 };
	__u32 id, map_type;
	int map_fd;

	if (!interval)
		return -EINVAL;

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
	map_type = info.type;
	id = info.id;

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);

	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */

		close(map_fd);
		map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
		if (map_fd < 0) {
                        return map_fd;
		} else if (id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			return 0;
		}

		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}

	return 0;
}
