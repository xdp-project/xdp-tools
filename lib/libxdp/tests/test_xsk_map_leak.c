// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <errno.h>
#include <linux/err.h>
#include <linux/membarrier.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test_utils.h"

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

#define MAX_NUM_QUEUES 4

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
};

static const char *opt_if;

static struct xsk_socket_info *xsks[MAX_NUM_QUEUES];

#define FRAME_SIZE 64
#define NUM_FRAMES (XSK_RING_CONS__DEFAULT_NUM_DESCS * 2)

/*
 * Trigger synchronize_rcu() in kernel, taken from kernel's
 * bpf selftests.
 */
static int kern_sync_rcu(void)
{
	return syscall(__NR_membarrier, MEMBARRIER_CMD_SHARED, 0, 0);
}

static int count_bpf_maps(bool list_maps)
{
	u32 id = 0;
	u32 next_id = 0;
	int err = 0;
	int count = 0;

	while (1) {
		err = bpf_map_get_next_id(id, &next_id);
		if (err) {
			if (err == -ENOENT)
				break;
			return err;
		}

		if (list_maps) {
			int fd = 0;
			struct bpf_map_info info = {};
			u32 info_len = sizeof(info);

			fd = bpf_map_get_fd_by_id(next_id);
			if (fd < 0) {
				return fd;
			}

			err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
			if (err) {
				close(fd);
				return err;
			}

			printf("Map %u, %s\n", info.id, info.name);
			close(fd);
		}

		count++;
		id = next_id;
	}

	return count;
}

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		exit(EXIT_FAILURE);

	DECLARE_LIBXDP_OPTS(xsk_umem_opts, opts,
		.size = size,
	);
	umem->umem = xsk_umem__create_opts(buffer, &umem->fq, &umem->cq, &opts);
	if (!umem->umem)
		exit(errno);

	umem->buffer = buffer;
	return umem;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
						    unsigned int qid)
{
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit(EXIT_FAILURE);

	xsk->umem = umem;
	rxr = &xsk->rx;
	DECLARE_LIBXDP_OPTS(xsk_socket_opts, opts,
		.rx = rxr,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
	);
	xsk->xsk = xsk_socket__create_opts(opt_if, qid, umem->umem, &opts);

	return xsk;
}

static struct xsk_socket_info *create_socket(u32 qid)
{
	struct xsk_umem_info *umem;
	void *buffs;

	if (posix_memalign(&buffs,
			   getpagesize(), /* PAGE_SIZE aligned */
			   NUM_FRAMES * FRAME_SIZE)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	umem = xsk_configure_umem(buffs, NUM_FRAMES * FRAME_SIZE);
	return xsk_configure_socket(umem, qid);
}

static void delete_socket(u32 qid)
{
	struct xsk_umem *umem;
	void *buff;

	buff = xsks[qid]->umem->buffer;
	umem = xsks[qid]->umem->umem;
	xsk_socket__delete(xsks[qid]->xsk);
	free(buff);
	(void)xsk_umem__delete(umem);
}

static void xsk_prog_detach(void)
{
	int ifindex = if_nametoindex(opt_if);
	struct xdp_multiprog *mp = NULL;
	int err = 0;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (libxdp_get_error(mp)) {
		fprintf(stderr, "Failed to get mp, error %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	err = xdp_multiprog__detach(mp);
	if (err) {
		fprintf(stderr, "Failed to get mp, error %s\n", strerror(-err));
		exit(EXIT_FAILURE);
	}

	xdp_multiprog__close(mp);
}

static void create_and_tear_down_xsk(void)
{
	u32 i;

	for (i = 0; i < MAX_NUM_QUEUES; i++) {
		xsks[i] = create_socket(i);
		if (libxdp_get_error(xsks[i]->xsk)) {
			fprintf(stderr, "Failed to create socket %u: %s\n",
					i, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	xsk_prog_detach();

	for (i = 0; i < MAX_NUM_QUEUES; i++)
		delete_socket(i);
}

static int read_args(int argc, char **argv)
{
	if (argc != 2)
		return -1;

	opt_if = argv[1];
	return 0;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int num_maps_before = 0;
	int num_maps_after = 0;

	if (read_args(argc, argv))
		return -1;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	silence_libbpf_logging();

	printf("Maps before:\n");
	num_maps_before = count_bpf_maps(true);
	if (num_maps_before < 0) {
		fprintf(stderr, "Failure on getting maps before, %s\n",
				strerror(-num_maps_before));
		exit(EXIT_FAILURE);
	}

	create_and_tear_down_xsk();
	kern_sync_rcu();

	printf("Maps after:\n");
	num_maps_after = count_bpf_maps(true);
	if (num_maps_after < 0) {
		fprintf(stderr, "Failure on getting maps after, %s\n",
				strerror(-num_maps_before));
		exit(EXIT_FAILURE);
	}

	if (num_maps_before != num_maps_after) {
		fprintf(stderr, "Maps leaked, before %d, after %d\n",
				num_maps_before, num_maps_after);
		exit(EXIT_FAILURE);
	}

	printf("Test map leaks PASSED\n");

	return 0;
}
