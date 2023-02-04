/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_dispatcher_v1.h"

#define XDP_METADATA_SECTION "xdp_metadata"
#define XDP_DISPATCHER_VERSION_V1 1
#define XDP_DISPATCHER_RETVAL 31


static volatile const struct xdp_dispatcher_config_v1 conf = {};

__attribute__ ((noinline))
int prog0(struct xdp_md *ctx) {
        volatile int ret = XDP_DISPATCHER_RETVAL;

        if (!ctx)
          return XDP_ABORTED;
        return ret;
}
__attribute__ ((noinline))

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx)
{
        __u8 num_progs_enabled = conf.num_progs_enabled;
        int ret;

        if (num_progs_enabled < 1)
                goto out;
        ret = prog0(ctx);
        if (!((1U << ret) & conf.chain_call_actions[0]))
                return ret;

out:
        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__uint(dispatcher_version, XDP_DISPATCHER_VERSION_V1) SEC(XDP_METADATA_SECTION);
