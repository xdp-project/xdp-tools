// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include <cap-ng.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "test_utils.h"

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_DESCS ((XSK_RING_PROD__DEFAULT_NUM_DESCS \
			+ XSK_RING_CONS__DEFAULT_NUM_DESCS) * 2)
#define UMEM_SIZE (NUM_DESCS * XSK_UMEM__DEFAULT_FRAME_SIZE)

static void run_privileged_operations(int ifindex, int queue_id, int *sock_fd)
{
	int xsks_map_fd = -1;

	if (xsk_setup_xdp_prog(ifindex, &xsks_map_fd) || xsks_map_fd < 0) {
		perror("xsk_setup_xdp_prog failed");
		exit(EXIT_FAILURE);
	}

	*sock_fd = socket(AF_XDP, SOCK_RAW, 0);
	if (*sock_fd < 0) {
		perror("socket(AF_XDP, ...) failed");
		exit(EXIT_FAILURE);
	}

	/* This call requires extra capabilities in older kernels, so keeping
	 * it in a privileged section.  And it's not supported on even older
	 * kernels, so not failing if that's the case. */
	if (bpf_map_update_elem(xsks_map_fd, &queue_id, sock_fd, 0)
	    && errno != EOPNOTSUPP) {
		perror("bpf_map_update_elem failed");
		exit(EXIT_FAILURE);
	}

	close(xsks_map_fd);
}

static void update_rlimit_memlock(void)
{
	struct rlimit rlim = { .rlim_cur = UMEM_SIZE, .rlim_max = UMEM_SIZE };

	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		perror("setrlimit(RLIMIT_MEMLOCK) failed");
		exit(EXIT_FAILURE);
	}
}

static void drop_capabilities(void)
{
	if (capng_get_caps_process()) {
		perror("capng_get_caps_process failed");
		exit(EXIT_FAILURE);
	}

	capng_clear(CAPNG_SELECT_BOTH);

	if (capng_apply(CAPNG_SELECT_BOTH)) {
		perror("capng_apply failed");
		exit(EXIT_FAILURE);
	}
}

static void run_non_privileged_preconfig(const char *ifname,
					 const char *ifname2,
					 int sock_fd)
{
	/* This call requires CAP_NET_RAW on kernels older than 5.7,
	 * so not checking the result.  It may fail or not, we do not
	 * rely on that much. */
	setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE,
		   ifname, strlen(ifname));

	/* The second update should always fail because it always
	 * requires CAP_NET_RAW. */
	if (!setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE,
		       ifname2, strlen(ifname2))) {
		perror("setsockopt(SO_BINDTODEVICE, ifname2) succeeded");
		exit(EXIT_FAILURE);
	}
}

static struct xsk_umem *create_umem_non_privileged(int sock_fd)
{
	struct xsk_umem_config config = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	};
	struct xsk_umem *umem = NULL;
	struct xsk_ring_cons cq;
	struct xsk_ring_prod fq;
	void *b;

	if (posix_memalign(&b, getpagesize(), UMEM_SIZE)) {
		perror("posix_memalign failed");
		exit(EXIT_FAILURE);
	}

	/* This variant requires CAP_NET_RAW, so should fail. */
	if (!xsk_umem__create(&umem, b, UMEM_SIZE,
			      &fq, &cq, &config) || umem) {
		perror("xsk_umem__create succeeded");
		exit(EXIT_FAILURE);
	}

	/* This variant shouldn't need any capabilities, so should pass. */
	if (xsk_umem__create_with_fd(&umem, sock_fd, b, UMEM_SIZE,
				     &fq, &cq, &config) || !umem) {
		perror("xsk_umem__create_with_fd failed");
		exit(EXIT_FAILURE);
	}

	return umem;
}

static struct xsk_socket *create_xsk_non_privileged(const char *ifname,
						    struct xsk_umem *umem,
						    int queue_id)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = XDP_USE_NEED_WAKEUP,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	};
	struct xsk_socket *xsk = NULL;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;

	if (xsk_socket__create(&xsk, ifname, queue_id,
			       umem, &rx, &tx, &cfg) || !xsk) {
		perror("xsk_socket__create failed");
		exit(EXIT_FAILURE);
	}

	return xsk;
}

int main(int argc, const char *argv[])
{
	const char *ifname, *ifname2;
	struct xsk_socket *xsk;
	struct xsk_umem *umem;
	int ifindex, queue_id;
	int sock_fd;

	silence_libbpf_logging();

	if (argc < 3) {
		printf("Usage: %s <interface> <interface>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	update_rlimit_memlock();

	ifname = argv[1];
	ifname2 = argv[2];
	queue_id = 0;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		perror("if_nametoindex(ifname) failed");
		exit(EXIT_FAILURE);
	}

	if (!if_nametoindex(ifname2)) {
		perror("if_nametoindex(ifname2) failed");
		exit(EXIT_FAILURE);
	}

	run_privileged_operations(ifindex, queue_id, &sock_fd);

	drop_capabilities();

	run_non_privileged_preconfig(ifname, ifname2, sock_fd);

	umem = create_umem_non_privileged(sock_fd);
	xsk = create_xsk_non_privileged(ifname, umem, queue_id);

	xsk_socket__delete(xsk);

	return EXIT_SUCCESS;
}
