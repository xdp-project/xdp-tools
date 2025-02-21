// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <errno.h>
#include <linux/err.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "test_utils.h"

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

#define MAX_EVENTS 10
#define MAX_NUM_QUEUES 4
#define TEST_NAME_LENGTH 128

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

/* Event holds socket operations that are run concurrently
 * and in theory can produce a race condition
 */
struct xsk_test_event {
	u32 num_create;
	u32 num_delete;
	u32 create_qids[MAX_NUM_QUEUES];	/* QIDs for sockets being created in this event */
	u32 delete_qids[MAX_NUM_QUEUES];	/* QIDs for sockets being deleted in this event */
};

struct xsk_test {
	char name[TEST_NAME_LENGTH];
	u32 num_events;
	struct xsk_test_event events[MAX_EVENTS];
};

/* Tests that use less queues must come first,
 * so we can run all possible tests on VMs with
 * small number of CPUs
 */
static struct xsk_test all_tests[] = {
	{ "Single socket created and deleted",
	  .num_events = 2,
	  .events = {{ .num_create = 1, .create_qids = {0} },
		     { .num_delete = 1, .delete_qids = {0} }
		    }},
	{ "2 sockets, created and deleted sequentially",
	  .num_events = 4,
	  .events = {{ .num_create = 1, .create_qids = {0} },
		     { .num_create = 1, .create_qids = {1} },
		     { .num_delete = 1, .delete_qids = {0} },
		     { .num_delete = 1, .delete_qids = {1} }
		    }},
	{ "2 sockets, created sequentially and deleted asynchronously",
	   .num_events = 3,
	   .events = {{ .num_create = 1, .create_qids = {0} },
		      { .num_create = 1, .create_qids = {1} },
		      { .num_delete = 2, .delete_qids = {0, 1} }
		     }},
	{ "2 sockets, asynchronously delete and create",
	  .num_events = 3,
	  .events = {{ .num_create = 1, .create_qids = {0} },
		     { .num_create = 1, .create_qids = {1},
		       .num_delete = 1, .delete_qids = {0} },
		     { .num_delete = 1, .delete_qids = {1} }
		    }},
	{ "3 sockets, created and deleted sequentially",
	  .num_events = 6,
	  .events = {{ .num_create = 1, .create_qids = {0} },
		     { .num_create = 1, .create_qids = {1} },
		     { .num_create = 1, .create_qids = {2} },
		     { .num_delete = 1, .delete_qids = {1} },
		     { .num_delete = 1, .delete_qids = {2} },
		     { .num_delete = 1, .delete_qids = {0} }
		    }},
};

# define ARRAY_SIZE(_x) (sizeof(_x) / sizeof((_x)[0]))

static const char *opt_if;
static const u8 num_tests = ARRAY_SIZE(all_tests);

static struct xsk_socket_info *xsks[MAX_NUM_QUEUES];

#define FRAME_SIZE 64
#define NUM_FRAMES (XSK_RING_CONS__DEFAULT_NUM_DESCS * 2)

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

static void *create_socket(void *args)
{
	struct xsk_umem_info *umem;
	u32 qid = *(u32 *)args;
	void *buffs;

	if (posix_memalign(&buffs,
			   getpagesize(), /* PAGE_SIZE aligned */
			   NUM_FRAMES * FRAME_SIZE)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	umem = xsk_configure_umem(buffs, NUM_FRAMES * FRAME_SIZE);
	xsks[qid] = xsk_configure_socket(umem, qid);

	return NULL;
}

static void *delete_socket(void *args)
{
	u32 qid = *(u32 *)args;
	struct xsk_umem *umem;
	void *buff;

	buff = xsks[qid]->umem->buffer;
	umem = xsks[qid]->umem->umem;
	xsk_socket__delete(xsks[qid]->xsk);
	free(buff);
	(void)xsk_umem__delete(umem);

	return NULL;
}

static bool xsk_prog_attached(void)
{
	char xsk_prog_name[] = "xsk_def_prog";
	int ifindex = if_nametoindex(opt_if);
	struct xdp_program *xsk_prog;
	struct xdp_multiprog *mp;
	bool answer = false;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (IS_ERR_OR_NULL(mp))
		return false;

	xsk_prog = xdp_multiprog__is_legacy(mp) ? xdp_multiprog__main_prog(mp) :
						  xdp_multiprog__next_prog(NULL, mp);

	if (IS_ERR_OR_NULL(xsk_prog))
		goto free_mp;

	answer = !strncmp(xsk_prog_name, xdp_program__name(xsk_prog),
			  sizeof(xsk_prog_name));
free_mp:
	xdp_multiprog__close(mp);
	return answer;
}

static void update_reference_refcnt(struct xsk_test_event *event, int *refcnt)
{
	*refcnt += event->num_create;
	*refcnt -= event->num_delete;
}

static bool check_run_event(struct xsk_test_event *event, int *refcnt)
{
	pthread_t threads[MAX_NUM_QUEUES];
	bool prog_attached, prog_needed;
	u8 thread_num = 0, i;
	int ret;

	update_reference_refcnt(event, refcnt);

	for (i = 0; i < event->num_create; i++) {
		ret = pthread_create(&threads[thread_num++], NULL,
				     &create_socket, &event->create_qids[i]);
		if (ret)
			exit(ret);
	}

	for (i = 0; i < event->num_delete; i++) {
		ret = pthread_create(&threads[thread_num++], NULL,
				     &delete_socket, &event->delete_qids[i]);
		if (ret)
			exit(ret);
	}

	for (i = 0; i < thread_num; i++)
		pthread_join(threads[i], NULL);

	prog_attached = xsk_prog_attached();
	prog_needed = *refcnt > 0;

	if (prog_needed != prog_attached) {
		printf("Program is referenced by %d sockets, but is %s attached\n",
		       *refcnt, prog_attached ? "still" : "not");
		return false;
	}

	return true;
}

static bool check_run_test(struct xsk_test *test)
{
	bool test_ok = false;
	int refcnt = 0;
	u8 i = 0;

	for (i = 0; i < test->num_events; i++) {
		if (!check_run_event(&test->events[i], &refcnt)) {
			printf("Event %u failed\n", i);
			goto print_result;
		}
	}

	/* Do not let tests interfere with each other */
	sleep(1);

	test_ok = true;

print_result:
	printf("%s: %s\n", test->name, test_ok ? "PASSED" : "FAILED");
	return test_ok;
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
	u8 i = 0;

	if (read_args(argc, argv))
		return -1;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	silence_libbpf_logging();

	for (i = 0; i < num_tests; i++) {
		if (!check_run_test(&all_tests[i]))
			exit(EXIT_FAILURE);
	}

	return 0;
}
