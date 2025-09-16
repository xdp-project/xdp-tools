#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <xdp/libxdp.h>

#include "logging.h"
#include "xdp-bench.h"

const struct xsk_opts defaults_xsk = {
	.attach_mode = XDP_MODE_NATIVE,
	.interval = 1,
	.retries = 3,
	.frame_size = 4096,
	.batch_size = 64,
	.tx_pkt_size = 64,
	.sched_policy = XSK_SCHED_OTHER,
	.clock = XSK_CLOCK_MONOTONIC,
};


int do_xsk(const void *cfg, __unused const char *pin_root_path)
{
	const struct xsk_opts *opt = cfg;

	return xsk_validate_opts(opt);
}
