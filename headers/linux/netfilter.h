#ifndef _LINUX_NETFILTER_H
#define _LINUX_NETFILTER_H

#include <stdbool.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#include "hlist.h"

struct flow_ports {
	__be16 source, dest;
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL,
	IP_CT_DIR_REPLY,
	IP_CT_DIR_MAX
};

enum flow_offload_tuple_dir {
	FLOW_OFFLOAD_DIR_ORIGINAL	= IP_CT_DIR_ORIGINAL,
	FLOW_OFFLOAD_DIR_REPLY		= IP_CT_DIR_REPLY,
	FLOW_OFFLOAD_DIR_MAX		= IP_CT_DIR_MAX,
};

enum flow_offload_type {
	NF_FLOW_OFFLOAD_UNSPEC,
	NF_FLOW_OFFLOAD_ROUTE,
};

enum nf_flow_flags {
	NF_FLOW_SNAT,
	NF_FLOW_DNAT,
	NF_FLOW_TEARDOWN,
	NF_FLOW_HW,
	NF_FLOW_HW_DYING,
	NF_FLOW_HW_DEAD,
	NF_FLOW_HW_PENDING,
	NF_FLOW_HW_BIDIRECTIONAL,
	NF_FLOW_HW_ESTABLISHED,
};

enum flow_offload_xmit_type {
	FLOW_OFFLOAD_XMIT_UNSPEC,
	FLOW_OFFLOAD_XMIT_NEIGH,
	FLOW_OFFLOAD_XMIT_XFRM,
	FLOW_OFFLOAD_XMIT_DIRECT,
	FLOW_OFFLOAD_XMIT_TC,
};

#define NF_FLOW_TABLE_ENCAP_MAX		2
struct flow_offload_tuple {
	union {
		struct in_addr		src_v4;
		struct in6_addr		src_v6;
	};
	union {
		struct in_addr		dst_v4;
		struct in6_addr		dst_v6;
	};
	struct {
		__be16			src_port;
		__be16			dst_port;
	};

	int				iifidx;

	__u8				l3proto;
	__u8				l4proto;
	struct {
		__u16			id;
		__be16			proto;
	} encap[NF_FLOW_TABLE_ENCAP_MAX];

	/* All members above are keys for lookups, see flow_offload_hash(). */
	struct { }			__hash;

	__u8				dir:2,
					xmit_type:3,
					encap_num:2,
					in_vlan_ingress:2;
	__u16				mtu;
	union {
		struct {
			struct dst_entry *dst_cache;
			__u32		dst_cookie;
		};
		struct {
			__u32		ifidx;
			__u32		hw_ifidx;
			__u8		h_source[ETH_ALEN];
			__u8		h_dest[ETH_ALEN];
		} out;
		struct {
			__u32		iifidx;
		} tc;
	};
};

struct flow_offload_tuple_rhash {
	struct rhash_head		node;
	struct flow_offload_tuple	tuple;
};

struct flow_offload {
	struct flow_offload_tuple_rhash		tuplehash[FLOW_OFFLOAD_DIR_MAX];
	struct nf_conn				*ct;
	unsigned long				flags;
	__u16					type;
	__u32					timeout;
};

#endif /* _LINUX_NETFILTER_H */
