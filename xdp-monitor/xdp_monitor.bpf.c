// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2017-2018 Jesper Dangaard Brouer, Red Hat Inc.
 *
 * XDP monitor tool, based on tracepoints
 */
#include <xdp/xdp_sample.bpf.h>
#include <xdp/xdp_sample_common.bpf.h>

char _license[] SEC("license") = "GPL";
