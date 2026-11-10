// SPDX-License-Identifier: GPL-2.0
/* Value layout of vlan_map, shared between xdp_forward.bpf.c and the
 * xdp-userspace-vlans.c loader half. The key is the VLAN device ifindex.
 * Both sides must see the same layout; including this header from both is
 * what enforces it.
 */
#ifndef XDP_FORWARD_VLAN_H
#define XDP_FORWARD_VLAN_H

struct vlan_info {
	int phys_ifindex;
	__u16 vlan_id;
	__u16 pad;
};

#endif /* XDP_FORWARD_VLAN_H */
