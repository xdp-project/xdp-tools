#ifndef COMMON_KERN_USER_H
#define COMMON_KERN_USER_H

#define FEAT_TCP	(1<<0)
#define FEAT_UDP	(1<<1)
#define FEAT_IPV6	(1<<2)
#define FEAT_IPV4	(1<<3)
#define FEAT_ETHERNET	(1<<4)
#define FEAT_ALL	(FEAT_TCP|FEAT_UDP|FEAT_IPV6|FEAT_IPV4|FEAT_ETHERNET)
#define FEAT_ALLOW	(1<<5)
#define FEAT_DENY	(1<<6)

#define MAP_FLAG_SRC (1<<0)
#define MAP_FLAG_DST (1<<1)
#define MAP_FLAG_TCP (1<<2)
#define MAP_FLAG_UDP (1<<3)
#define MAP_FLAGS (MAP_FLAG_SRC|MAP_FLAG_DST|MAP_FLAG_TCP|MAP_FLAG_UDP)

#define COUNTER_SHIFT 6

#define MAP_NAME_PORTS filter_ports
#define MAP_NAME_IPV4 filter_ipv4
#define MAP_NAME_IPV6 filter_ipv6
#define MAP_NAME_ETHERNET filter_ethernet

#include "xdp/xdp_stats_kern_user.h"

#endif
