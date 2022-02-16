/* SPDX-License-Identifier: GPL-2.0 */

/* Used by BPF-prog kernel side BPF-progs and userspace programs,
 * for sharing xdp_stats common struct and DEFINEs.
 */
#ifndef __XDP_STATS_KERN_USER_H
#define __XDP_STATS_KERN_USER_H

/* This is the data record stored in the map */
struct xdp_stats_record {
	union {
		__u64 packets;
		__u64 rx_packets;
	};
	union {
		__u64 bytes;
		__u64 rx_bytes;
	};
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#define XDP_STATS_MAP_NAME xdp_stats_map

#endif /* __XDP_STATS_KERN_USER_H */
