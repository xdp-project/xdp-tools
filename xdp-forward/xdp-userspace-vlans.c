// SPDX-License-Identifier: GPL-2.0

#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <bpf/bpf.h>

#include "logging.h"
#include "params.h"
#include "xdp_forward_vlan.h"
#include "xdp-userspace-vlans.h"


/*
 * Pull the VLAN id out of a nested IFLA_INFO_DATA attribute. Returns 0 if
 * the attribute carries no IFLA_VLAN_ID (0 is not a valid tag), and for
 * devices whose encapsulation is not plain 802.1Q: the BPF program only
 * reshapes single 802.1Q tags, so 802.1ad uppers must stay out of the map.
 */
static __u16 vlan_id_from_info_data(const struct rtattr *info_data)
{
	const struct rtattr *rta;
	int rem = RTA_PAYLOAD(info_data);
	__be16 proto = htobe16(ETH_P_8021Q);
	__u16 vid = 0;

	for (rta = RTA_DATA(info_data); RTA_OK(rta, rem);
	     rta = RTA_NEXT(rta, rem)) {
		if (rta->rta_type == IFLA_VLAN_ID)
			vid = *(__u16 *)RTA_DATA(rta);
		else if (rta->rta_type == IFLA_VLAN_PROTOCOL)
			proto = *(__be16 *)RTA_DATA(rta);
	}

	if (proto != htobe16(ETH_P_8021Q))
		return 0;
	return vid;
}

/*
 * Inspect one RTM_NEWLINK message. Returns the link's own ifindex for any
 * VLAN device (so the stacked-parent check below sees every VLAN link,
 * including rejected ones), 0 for non-VLAN links. usable marks the ones
 * that may enter the map; rejected on purpose: non-802.1Q encapsulation,
 * links whose parent lives in another netns (IFLA_LINK is then an ifindex
 * in the parent's namespace, meaningless here and free to collide with a
 * local TX-port), and links with a master device (IFLA_MASTER: a bridge,
 * bond or VRF port is not a plain routed egress).
 */
static int parse_vlan_link(const struct nlmsghdr *nlh, __u16 *vlan_id,
			   int *phys_ifindex, int *usable)
{
	const struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	const struct rtattr *rta;
	int rem = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	int is_vlan = 0, lower = 0, foreign_parent = 0, has_master = 0;
	__u16 vid = 0;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) {
		if (rta->rta_type == IFLA_LINK) {
			lower = *(int *)RTA_DATA(rta);
		} else if (rta->rta_type == IFLA_LINK_NETNSID) {
			foreign_parent = 1;
		} else if (rta->rta_type == IFLA_MASTER) {
			has_master = 1;
		} else if (rta->rta_type == IFLA_LINKINFO) {
			const struct rtattr *li;
			int li_rem = RTA_PAYLOAD(rta);

			for (li = RTA_DATA(rta); RTA_OK(li, li_rem);
			     li = RTA_NEXT(li, li_rem)) {
				if (li->rta_type == IFLA_INFO_KIND)
					is_vlan = !strcmp(RTA_DATA(li), "vlan");
				else if (li->rta_type == IFLA_INFO_DATA)
					vid = vlan_id_from_info_data(li);
			}
		}
	}

	if (!is_vlan)
		return 0;

	*vlan_id = vid;
	*phys_ifindex = lower;
	*usable = vid && lower && !foreign_parent && !has_master;
	return ifi->ifi_index;
}

static int send_getlink_dump(int sock)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifi));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0)
		return -errno;
	return 0;
}

static int collect_vlan_links(int sock, struct vlan_entry **entries)
{
	char buf[32768];
	struct vlan_entry *list = NULL;
	int count = 0, cap = 0;

	for (;;) {
		struct nlmsghdr *nlh;
		int len;

		len = recv(sock, buf, sizeof(buf), MSG_TRUNC);
		if (len < 0) {
			free(list);
			return -errno;
		}
		if (len > (int)sizeof(buf)) {
			/* silently losing links would mean silent XDP_PASS
			 * for their VLANs; refuse instead
			 */
			free(list);
			return -EMSGSIZE;
		}

		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
		     nlh = NLMSG_NEXT(nlh, len)) {
			struct vlan_entry e;

			if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
				/* link table changed mid-dump; the snapshot
				 * is inconsistent, retry from scratch
				 */
				free(list);
				return -EINTR;
			}
			if (nlh->nlmsg_type == NLMSG_DONE) {
				*entries = list;
				return count;
			}
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(nlh);

				free(list);
				return err->error ? err->error : -EIO;
			}
			if (nlh->nlmsg_type != RTM_NEWLINK)
				continue;

			e.vlan_ifindex = parse_vlan_link(nlh, &e.vlan_id,
							 &e.phys_ifindex,
							 &e.usable);
			if (!e.vlan_ifindex)
				continue;

			if (count == cap) {
				struct vlan_entry *n;

				cap = cap ? cap * 2 : 64;
				n = realloc(list, cap * sizeof(*list));
				if (!n) {
					free(list);
					return -ENOMEM;
				}
				list = n;
			}
			list[count++] = e;
		}
	}
}

/*
 * Prune in two passes so the stacked-parent check always sees the FULL
 * dump: a VLAN stacked on another VLAN must be dropped even when the
 * middle VLAN was itself rejected, so the scan runs over every collected
 * link, and compaction only happens afterwards.
 */
int vlan_collect_entries(const struct iface *ifaces,
			 struct vlan_entry **out)
{
	struct vlan_entry *entries = NULL;
	int i, j, sock, ret, tries, kept = 0;
	int count = -EINTR;

	for (tries = 0; tries < 3 && count == -EINTR; tries++) {
		sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
			      NETLINK_ROUTE);
		if (sock < 0)
			return -errno;

		ret = send_getlink_dump(sock);
		if (ret) {
			close(sock);
			return ret;
		}

		count = collect_vlan_links(sock, &entries);
		close(sock);
	}
	if (count < 0)
		return count;

	for (i = 0; i < count; i++) {
		const struct iface *iface;
		int keep = entries[i].usable;

		for (j = 0; keep && j < count; j++)
			if (entries[i].phys_ifindex == entries[j].vlan_ifindex)
				keep = 0;

		if (keep) {
			keep = 0;
			for (iface = ifaces; iface; iface = iface->next)
				if (iface->ifindex == entries[i].phys_ifindex)
					keep = 1;
		}

		entries[i].usable = keep;
	}

	for (i = 0; i < count; i++)
		if (entries[i].usable)
			entries[kept++] = entries[i];

	if (!kept) {
		free(entries);
		*out = NULL;
		return 0;
	}

	*out = entries;
	return kept;
}

int vlan_populate_map(int map_fd, const struct vlan_entry *entries, int count)
{
	int i, ret, mapped = 0, map_full = 0;

	for (i = 0; i < count; i++) {
		struct vlan_info info = {
			.phys_ifindex = entries[i].phys_ifindex,
			.vlan_id = entries[i].vlan_id,
		};

		/* libbpf >= 1.0 returns -errno directly */
		ret = bpf_map_update_elem(map_fd, &entries[i].vlan_ifindex,
					  &info, 0);
		if (ret == -E2BIG) {
			map_full = 1;
			continue;
		}
		if (ret)
			return ret;
		mapped++;
	}

	if (map_full)
		pr_warn("vlan_map full: some VLAN devices will use the stack path\n");
	pr_debug("mapped %d VLAN devices\n", mapped);
	return 0;
}
