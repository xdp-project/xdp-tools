// SPDX-License-Identifier: GPL-2.0
#ifndef XDP_USERSPACE_VLANS_H
#define XDP_USERSPACE_VLANS_H

#include <linux/types.h>

struct iface;

struct vlan_entry {
	int vlan_ifindex;
	int phys_ifindex;
	__u16 vlan_id;
	int usable;
};

/* Dump the VLAN links via netlink and prune to the entries usable as XDP
 * egress translations (single 802.1Q, local parent, no master, parent not
 * itself a VLAN) whose parent is one of the configured interfaces. Returns
 * the number of entries and the pruned list in *entries (caller frees; NULL
 * when the count is 0), or a negative errno.
 */
int vlan_collect_entries(const struct iface *ifaces,
			 struct vlan_entry **entries);

/* Write the collected entries into vlan_map. Returns 0 or a negative errno;
 * a full map is not an error, the excess VLANs just stay on the stack path.
 */
int vlan_populate_map(int map_fd, const struct vlan_entry *entries,
		      int count);

#endif /* XDP_USERSPACE_VLANS_H */
