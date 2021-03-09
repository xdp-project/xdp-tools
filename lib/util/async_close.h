/* SPDX-License-Identifier: GPL-2.0 */

/* This is a temporary workaround for the blocking close for bpf_link fds. We
 * try a best effort asynchronous close operation, failing which we fall back to
 * the normal close(2).
 *
 * We only submit SQEs, but don't really consume the result, but still advance
 * so as to not breach our CQE overflow limits and get -EBUSY back when doing
 * io_uring_enter.
 *
 * At initialization time, the constructor checks if the IORING_OP_CLOSE opcode
 * is supported, and sets a bool indicating the status. This allows us to avoid
 * setting up and tearing down the mappings each time async_close is called.
 */

#ifndef __ASYNC_CLOSE_H
#define __ASYNC_CLOSE_H

#include <linux/io_uring.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#define XDP_URING_OP_CLOSE 19

static bool avail_op_close = false;

static inline int __io_uring_setup(unsigned int entries,
				   struct io_uring_params *p)
{
	return (int)syscall(__NR_io_uring_setup, entries, p);
}

static inline int __io_uring_enter(int ring_fd, unsigned int to_submit,
				   unsigned int min_complete,
				   unsigned int flags)
{
	return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit,
			    min_complete, flags, NULL, 0);
}

static inline void submit_close_sqe(struct io_uring_sqe *sqe_ptr,
				    unsigned int *sq_array,
				    unsigned int *sqe_ring_tail,
				    unsigned int *sq_ring_mask, int fd)
{
	unsigned int tail, index;

	/* There's always a free SQE slot, as they're consumed on enter */
	tail = __atomic_load_n(sqe_ring_tail, __ATOMIC_RELAXED);
	index = tail & *sq_ring_mask;
	sqe_ptr[index].fd = fd;
	sqe_ptr[index].opcode = XDP_URING_OP_CLOSE;
	sq_array[index] = index;
	__atomic_store_n(sqe_ring_tail, tail + 1, __ATOMIC_RELEASE);
}

static inline void consume_close_cqe(unsigned int *cqe_ring_head)
{
	/* We don't really care about the result, so just advance head.  This
	 * also means the update to head can be a relaxed store, as we don't
	 * really read anything, so it is fine. Also, a future submit will
	 * ensure this is visible before we enter the kernel again.
	 */
	unsigned int head = __atomic_load_n(cqe_ring_head, __ATOMIC_RELAXED);
	__atomic_store_n(cqe_ring_head, head + 1, __ATOMIC_RELAXED);
}

static int __async_close(int close_fd, bool feature)
{
	unsigned int *sq_ring_mask, *sq_array, *cqe_ring_head, *sqe_ring_tail;
	size_t sq_len, sqe_len, cqe_len;
	struct io_uring_sqe *sqe_ptr;
	struct io_uring_params p;
	void *sq_ptr, *cqe_ptr;
	int fd;
	int r = -1;

	memset(&p, 0, sizeof(p));
	fd = __io_uring_setup(2, &p);
	if (fd < 0)
		return fd;

	sq_len = p.sq_off.array + p.sq_entries * sizeof(unsigned int);
	cqe_len = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

	sq_ptr = mmap(NULL, sq_len, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (sq_ptr == MAP_FAILED)
		goto close_fd;

	cqe_ptr = mmap(NULL, cqe_len, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
	if (cqe_ptr == MAP_FAILED)
		goto unmap_sq_ptr;

	cqe_ring_head = cqe_ptr + p.cq_off.head;

	sqe_ring_tail = sq_ptr + p.sq_off.tail;
	sq_ring_mask = sq_ptr + p.sq_off.ring_mask;
	sq_array = sq_ptr + p.sq_off.array;

	sqe_len = p.sq_entries * sizeof(struct io_uring_sqe);
	sqe_ptr = mmap(NULL, sqe_len, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqe_ptr == MAP_FAILED)
		goto unmap_cqe_ptr;

	if (feature) {
		/* We perform feature detection for the CLOSE op by trying to close the
		 * io_uring fd itself.  This should fail with -EINVAL if the op isn't
		 * supported, otherwise it should return -EBADF on the completion queue.
		 */
		close_fd = fd;
	}
	submit_close_sqe(sqe_ptr, sq_array, sqe_ring_tail, sq_ring_mask,
			 close_fd);
	r = __io_uring_enter(fd, 1, 0, 0);
	if (r < 0)
		goto unmap_sqe_ptr;
	consume_close_cqe(cqe_ring_head);

unmap_sqe_ptr:
	munmap(sqe_ptr, sqe_len);
unmap_cqe_ptr:
	munmap(cqe_ptr, cqe_len);
unmap_sq_ptr:
	munmap(sq_ptr, sq_len);
close_fd:
	close(fd);
	return r;
}

__attribute__((constructor)) static void __async_close_check_op()
{
	/* The completion is always done inline, so if this fails with -EINVAL,
	 * IORING_OP_CLOSE is unsupported.
	 */
	avail_op_close = __async_close(-1, true) < 0 ? false : true;
}

static void async_close(int fd)
{
	int r;

	if (!avail_op_close)
		goto out;
	r = __async_close(fd, false);
	if (r < 0)
		goto out;
	return;
out:
	close(fd);
}

#endif
