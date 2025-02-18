// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include <errno.h>
#include <inttypes.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include "test_utils.h"

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_DESCS ((XSK_RING_PROD__DEFAULT_NUM_DESCS \
			+ XSK_RING_CONS__DEFAULT_NUM_DESCS) * 2)
#define UMEM_SIZE (NUM_DESCS * XSK_UMEM__DEFAULT_FRAME_SIZE)

static void update_rlimit_memlock(void)
{
	struct rlimit rlim = { .rlim_cur = UMEM_SIZE, .rlim_max = UMEM_SIZE };

	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		perror("setrlimit(RLIMIT_MEMLOCK) failed");
		exit(EXIT_FAILURE);
	}
}

static struct xsk_umem *create_umem_with_flags()
{
	struct xsk_umem *umem = NULL;
	struct xsk_ring_cons cq;
	struct xsk_ring_prod fq;
	void *b;

	if (posix_memalign(&b, getpagesize(), UMEM_SIZE)) {
		perror("posix_memalign failed");
		exit(EXIT_FAILURE);
	}

	/* This variant uses a frame_size that is not a power of 2 without
	 * flags, should fail. */
	DECLARE_LIBXDP_OPTS(xsk_umem_opts, opts_no_flags,
		.size = UMEM_SIZE - 1,
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE - 1,
	);
	umem = xsk_umem__create_opts(b, &fq, &cq, &opts_no_flags);
	if (umem) {
		perror("xsk_umem__create_opts with odd frame_size "
		       "unexpectedly succeeded");
		exit(EXIT_FAILURE);
	}

	/* This variant uses a frame_size that is not a power of 2 with flags,
	 * should succeed.
	 *
	 * A failure here may indicate a mismatch in struct xdp_umem_reg
	 * between user space and kernel space, and that fall back processing
	 * is happening in the kernel. (Ref: LP: #2098005 and PR #477).
	 */
	DECLARE_LIBXDP_OPTS(xsk_umem_opts, opts,
		.size = UMEM_SIZE - 1,
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE - 1,
		.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG,
	);
	umem = xsk_umem__create_opts(b, &fq, &cq, &opts);
	if (!umem) {
		perror("xsk_umem__create_opts failed");
		exit(EXIT_FAILURE);
	}

	return umem;
}

static struct xsk_socket *create_xsk(const char *ifname, struct xsk_umem *umem,
				     int queue_id)
{
	struct xsk_socket *xsk = NULL;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;

	DECLARE_LIBXDP_OPTS(xsk_socket_opts, opts,
		.rx = &rx,
		.tx = &tx,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_USE_NEED_WAKEUP,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	);
	xsk = xsk_socket__create_opts(ifname, queue_id, umem, &opts);
	if (!xsk) {
		perror("xsk_socket__create_opts failed");
		exit(EXIT_FAILURE);
	}

	return xsk;
}

int main(int argc, const char *argv[])
{
	struct xsk_socket *xsk;
	struct xsk_umem *umem;
	int ifindex, queue_id;
	const char *ifname;

	silence_libbpf_logging();

	if (argc < 2) {
		printf("Usage: %s <interface>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	update_rlimit_memlock();

	ifname = argv[1];
	queue_id = 0;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		perror("if_nametoindex(ifname) failed");
		exit(EXIT_FAILURE);
	}

	umem = create_umem_with_flags();
	xsk = create_xsk(ifname, umem, queue_id);

	xsk_socket__delete(xsk);

	return EXIT_SUCCESS;
}
