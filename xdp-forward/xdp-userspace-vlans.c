// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#define MAX_VLANS_PER_IFACE 16
struct vlan_info {
	__u16 vlan_id; // VLAN ID
	int phys_ifindex; // Physical interface index
	int vlan_ifindex; // VLAN interface index
};

static int init_netlink_socket()
{
	struct sockaddr_nl addr;
	int sock;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		perror("Failed to open netlink socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = 0;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Failed to bind netlink socket");
		close(sock);
		return -1;
	}
	return sock;
}

static int send_getlink_request(int sock)
{
	struct sockaddr_nl addr;
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.nlh.nlmsg_pid = getpid();
	req.ifm.ifi_family = AF_PACKET; // request all interfaces

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		perror("Failed to send netlink message");
		return -1;
	}
	return 0;
}

static int parse_vlan_id_from_data(struct rtattr *li_attr)
{
	struct rtattr *vlan_attr;
	int vlan_remaining = RTA_PAYLOAD(li_attr);
	int vlan_id = 0;

	for (vlan_attr = (struct rtattr *)RTA_DATA(li_attr);
	     RTA_OK(vlan_attr, vlan_remaining);
	     vlan_attr = RTA_NEXT(vlan_attr, vlan_remaining)) {
		if (vlan_attr->rta_type == IFLA_VLAN_ID) {
			vlan_id = *(uint16_t *)RTA_DATA(vlan_attr);
			break; // vid found
		}
	}
	return vlan_id;
}

static void parse_link_info_attr(struct rtattr *attr, int *is_vlan,
				 int *vlan_id)
{
	struct rtattr *li_attr;
	int li_remaining = RTA_PAYLOAD(attr);

	for (li_attr = (struct rtattr *)RTA_DATA(attr);
	     RTA_OK(li_attr, li_remaining);
	     li_attr = RTA_NEXT(li_attr, li_remaining)) {
		if (li_attr->rta_type == IFLA_INFO_KIND) {
			char *kind = RTA_DATA(li_attr);
			if (strncmp(kind, "vlan", 4) == 0)
				*is_vlan = 1;

		} else if (li_attr->rta_type == IFLA_INFO_DATA) {
			int vid = parse_vlan_id_from_data(li_attr);
			if (vid) // first valid vid is 1
				*vlan_id = vid;
		}
	}
}

static void parse_interface_attributes(struct nlmsghdr *nlmsg, int *is_vlan,
				       int *vlan_id, int *link_ifindex)
{
	struct ifinfomsg *ifinfo = NLMSG_DATA(nlmsg);
	struct rtattr *attr;
	int remaining =
		nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

	*is_vlan = 0;
	*vlan_id = 0;
	*link_ifindex = -1;

	for (attr = IFLA_RTA(ifinfo); RTA_OK(attr, remaining);
	     attr = RTA_NEXT(attr, remaining)) {
		if (attr->rta_type == IFLA_LINKINFO)
			parse_link_info_attr(attr, is_vlan, vlan_id);
		else if (attr->rta_type == IFLA_LINK)
			*link_ifindex = *(int *)RTA_DATA(attr);
	}
}

static void handle_found_vlan(struct ifinfomsg *ifinfo, int vlan_id,
			      int link_ifindex, struct vlan_info *vlan_list,
			      int *found_vlans)
{
	if (*found_vlans < 1024) {
		printf("%d\t%d\n", vlan_id, ifinfo->ifi_index);
		vlan_list[*found_vlans].vlan_id = vlan_id;
		vlan_list[*found_vlans].phys_ifindex = link_ifindex;
		vlan_list[*found_vlans].vlan_ifindex = ifinfo->ifi_index;
		(*found_vlans)++;
	} else
		fprintf(stderr, "Warning: VLAN list capacity exceeded.\n");
}

static int process_netlink_message(struct nlmsghdr *nlmsg, int target_ifindex,
				   struct vlan_info *vlan_list,
				   int *found_vlans)
{
	struct ifinfomsg *ifinfo;
	int is_vlan, vlan_id, link_ifindex;

	if (nlmsg->nlmsg_type == NLMSG_DONE)
		return NLMSG_DONE; // all msgs processed

	if (nlmsg->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlmsg);
		// If the error field is zero, it's an ACK, not an error. Ignore.
		if (err->error == 0)
			return NLMSG_DONE;

		errno = -err->error;
		perror("Netlink error");
		return NLMSG_ERROR;
	}

	if (nlmsg->nlmsg_type != RTM_NEWLINK)
		return 0;

	ifinfo = NLMSG_DATA(nlmsg);
	parse_interface_attributes(nlmsg, &is_vlan, &vlan_id, &link_ifindex);

	if (is_vlan && link_ifindex == target_ifindex && vlan_id)
		handle_found_vlan(ifinfo, vlan_id, link_ifindex, vlan_list,
				  found_vlans);

	return 0;
}

static int receive_and_process_responses(int sock, int target_ifindex,
					 struct vlan_info *vlan_list)
{
	char buf[8192];
	int found_vlans = 0;
	int status;

	printf("VLAN interfaces using physical ifindex %d:\n", target_ifindex);
	printf("VLAN ID\tVLAN ifindex\n");

	while (1) {
		int len = recv(sock, buf, sizeof(buf), 0);
		if (len < 0) {
			perror("Failed to receive netlink message");
			return -1;
		}

		struct nlmsghdr *nlmsg;
		for (nlmsg = (struct nlmsghdr *)buf; NLMSG_OK(nlmsg, len);
		     nlmsg = NLMSG_NEXT(nlmsg, len)) {
			status = process_netlink_message(
				nlmsg, target_ifindex, vlan_list, &found_vlans);

			if (status == NLMSG_DONE)
				return found_vlans;

			if (status == NLMSG_ERROR)
				return -1;
		}
		if (len > 0 && !NLMSG_OK(nlmsg, len))
			fprintf(stderr,
				"Warning: Potentially incomplete netlink message processed.\n");
	}
	return found_vlans;
}

int find_vlan_interfaces(int target_ifindex, struct vlan_info *vlan_list)
{
	/**
    * find_vlan_interfaces - Find VLAN interfaces linked
    * to a given physical interface as well as VLAN id
    * assigned to that VLAN interface. netlink socket is
    * used. 
    * This function is called for each physical interface,
    * where our program should be attached, their VLAN
    * interfaces are found and added to the map.
    */
	int sock;
	int result = -1;

	sock = init_netlink_socket();
	if (sock < 0)
		return -1;

	if (send_getlink_request(sock) < 0) {
		close(sock);
		return -1;
	}

	result = receive_and_process_responses(sock, target_ifindex, vlan_list);

	close(sock);
	return result; // Returns count of found VLANs or -1 on error
}
