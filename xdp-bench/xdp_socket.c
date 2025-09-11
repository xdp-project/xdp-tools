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
	.mode = XDP_MODE_NATIVE,
	.interval = 1,
	.retries = 3,
	.frame_size = 4096,
	.batch_size = 64,
	.sched_policy = XSK_SCHED_OTHER,
	.clock = XSK_CLOCK_MONOTONIC,
};


int do_xsk(const void *cfg, __unused const char *pin_root_path)
{
	const struct xsk_opts *opt = cfg;

	if (opt->shared_umem && opt->reduce_cap) {
		pr_warn("Can't use --shared-umem and --reduce_cap together.\n");
		return -1;
	}

	if (opt->mode == XDP_MODE_SKB && opt->copy_mode == XSK_COPY_ZEROCOPY) {
		pr_warn("Can't use zero-copy and skb mode together.\n");
		return -1;
	}

	if (!opt->unaligned && opt->frame_size & (opt->frame_size -1)) {
		pr_warn("Frame size %u is not a power of two.\n", opt->frame_size);
		return -1;
	}

	return 0;
}
