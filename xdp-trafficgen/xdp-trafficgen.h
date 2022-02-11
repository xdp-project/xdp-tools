/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDP_TRAFFICGEN_H
#define XDP_TRAFFICGEN_H

#include <linux/bpf.h>

struct trafficgen_config {
  int ifindex_out;
  __u16 port_start;
  __u16 port_range;
};

struct trafficgen_state {
  __u16 next_port;
};

#endif
