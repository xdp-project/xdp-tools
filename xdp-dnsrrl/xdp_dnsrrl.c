/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#include <net/if.h>
#include <assert.h>
#include <getopt.h>
#include <sys/types.h>
#include <string.h>

#include <linux/if_link.h>

#include "xdp_dnsrrl_kern.skel.h"

#define DEFAULT_IPv4_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v4_prefixes"
#define DEFAULT_IPv6_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v6_prefixes"
#define DEFAULT_RATELIMIT 0x20
#define DEFAULT_CPUS 0x2

#define EXCLv4_TBL "exclude_v4_prefixes"
#define EXCLv6_TBL "exclude_v6_prefixes"

static unsigned int ifindex;

static unsigned long ratelimit = DEFAULT_RATELIMIT;
static unsigned long cpus = DEFAULT_CPUS;

static const struct loadopt {
        bool help;
        struct iface iface;
        enum xdp_attach_mode mode;
} defaults_load = {
        .mode = XDP_MODE_NATIVE,
};

struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {NULL, 0}
};

static struct prog_option load_options[] = {
        DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
                      .short_opt = 'm',
                      .typearg = xdp_modes,
                      .metavar = "<mode>",
                      .help = "Load XDP program in <mode>; default native"),
        DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
                      .positional = true,
                      .metavar = "<ifname>",
                      .required = true,
                      .help = "Load on device <ifname>"),
        END_OPTIONS
};


int main(int argc, char **argv)
{
}
