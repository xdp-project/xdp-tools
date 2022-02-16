/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "stats.h"
#include "util.h"
#include "logging.h"

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static int gettime(__u64 *nstime)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		pr_warn("Error with gettimeofday! (%i)\n", res);
		return res;
	}

	*nstime = (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
	return 0;
}

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double)period / NANOSEC_PER_SEC);

	return period_;
}

int stats_print_one(struct stats_record *stats_rec)
{
	__u64 packets, bytes;
	struct record *rec;
	int i, err;

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++) {
		char *fmt = "  %-35s %'11lld pkts %'11lld KiB\n";
		const char *action = action2str(i);

		rec = &stats_rec->stats[i];
		packets = rec->total.rx_packets;
		bytes = rec->total.rx_bytes;

		if (rec->enabled) {
			err = printf(fmt, action, packets, bytes / 1024);
			if (err < 0)
				return err;
		}
	}

	return 0;
}

int stats_print(struct stats_record *stats_rec, struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	struct timespec t;
	bool first = true;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i, err;

	err = clock_gettime(CLOCK_REALTIME, &t);
	if (err < 0) {
		pr_warn("Error with gettimeofday! (%i)\n", err);
		return err;
	}

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++) {
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			    " %'11lld KiB (%'6.0f Mbits/s)\n";
		const char *action = action2str(i);

		rec = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		if (!rec->enabled)
			continue;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		bytes   = rec->total.rx_bytes - prev->total.rx_bytes;

		period = calc_period(rec, prev);
		if (period == 0)
			return 0;

		if (first) {
			printf("Period of %fs ending at %ld.%06ld\n", period,
			       (long) t.tv_sec, (long) t.tv_nsec / 1000);
			first = false;
		}

		pps = packets / period;

		bps = (bytes * 8) / period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1024, bps, period);
	}
	printf("\n");

	return 0;
}

/* BPF_MAP_TYPE_ARRAY */
static int map_get_value_array(int fd, __u32 key, struct xdp_stats_record *value)
{
	int err = 0;

	err = bpf_map_lookup_elem(fd, &key, value);
	if (err)
		pr_debug("bpf_map_lookup_elem failed key:0x%X\n", key);

	return err;
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
static int map_get_value_percpu_array(int fd, __u32 key, struct xdp_stats_record *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	int nr_cpus = libbpf_num_possible_cpus();
	struct xdp_stats_record *values;
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i, err;

	if (nr_cpus < 0)
		return nr_cpus;

	values = calloc(nr_cpus, sizeof(*values));
	if (!values)
		return -ENOMEM;

	err = bpf_map_lookup_elem(fd, &key, values);
	if (err) {
		pr_debug("bpf_map_lookup_elem failed key:0x%X\n", key);
		goto out;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
out:
	free(values);
	return err;
}

static int map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct xdp_stats_record value = {};
	int err;

	/* Get time as close as possible to reading map contents */
	err = gettime(&rec->timestamp);
	if (err)
		return err;

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

int stats_collect(int map_fd, __u32 map_type, struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;
	int err;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		if (!stats_rec->stats[key].enabled)
			continue;

		err = map_collect(map_fd, map_type, key,
				  &stats_rec->stats[key]);
		if (err)
			return err;
	}

	return 0;
}

static int check_map_pin(__u32 map_id, const char *pin_dir, const char *map_name)
{
	struct bpf_map_info info = {};
	int fd, ret = 0;

	fd = get_pinned_map_fd(pin_dir, map_name, &info);
	if (fd < 0) {
		if (fd == -ENOENT)
			pr_warn("Stats map disappeared while polling\n");
		else
			pr_warn("Unable to re-open stats map\n");
		return fd;
	}

	if (info.id != map_id) {
		pr_warn("Stats map ID changed while polling\n");
		ret = -EINVAL;
	}
	close(fd);

	return ret;
}

int stats_poll(int map_fd, int interval, bool *exit,
	       const char *pin_dir, const char *map_name)
{
	struct bpf_map_info info = {};
	struct stats_record prev, record = { 0 };
	__u32 info_len = sizeof(info);
	__u32 map_type, map_id;
	int err;

	record.stats[XDP_DROP].enabled = true;
	record.stats[XDP_PASS].enabled = true;
	record.stats[XDP_REDIRECT].enabled = true;
	record.stats[XDP_TX].enabled = true;

	if (!interval)
		return -EINVAL;

	err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
	if (err)
		return -errno;
	map_type = info.type;
	map_id = info.id;

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);

	usleep(1000000 / 4);

	while (!*exit) {
		if (pin_dir) {
			err = check_map_pin(map_id, pin_dir, map_name);
			if (err)
				return err;
		}

		memset(&info, 0, sizeof(info));
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		err = stats_print(&record, &prev);
		if (err)
			return err;
		usleep(interval * 1000);
	}

	return 0;
}
