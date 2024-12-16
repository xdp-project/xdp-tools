/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * AF_XDP user-space access library.
 *
 * Copyright(c) 2018 - 2021 Intel Corporation.
 *
 * Author(s): Magnus Karlsson <magnus.karlsson@intel.com>
 */

/* So as not to clash with these functions when they where part of libbpf */
#ifndef __LIBBPF_XSK_H
#define __LIBBPF_XSK_H

#include <stdio.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <linux/if_xdp.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC_STDC_INLINE__
#define XDP_ALWAYS_INLINE inline __attribute__((__always_inline__))
#elif __GNUC_GNU_INLINE__
#define XDP_ALWAYS_INLINE static inline __attribute__((__always_inline__))
#else
#define XDP_ALWAYS_INLINE static inline
#endif

/* Do not access these members directly. Use the functions below. */
#define DEFINE_XSK_RING(name) \
struct name { \
	__u32 cached_prod; \
	__u32 cached_cons; \
	__u32 mask; \
	__u32 size; \
	__u32 *producer; \
	__u32 *consumer; \
	void *ring; \
	__u32 *flags; \
}

DEFINE_XSK_RING(xsk_ring_prod);
DEFINE_XSK_RING(xsk_ring_cons);

/* For a detailed explanation on the memory barriers associated with the
 * ring, please take a look at net/xdp/xsk_queue.h in the Linux kernel source tree.
 */

struct xsk_umem;
struct xsk_socket;

XDP_ALWAYS_INLINE __u64 *xsk_ring_prod__fill_addr(struct xsk_ring_prod *fill,
						  __u32 idx)
{
	__u64 *addrs = (__u64 *)fill->ring;

	return &addrs[idx & fill->mask];
}

XDP_ALWAYS_INLINE const __u64 *
xsk_ring_cons__comp_addr(const struct xsk_ring_cons *comp, __u32 idx)
{
	const __u64 *addrs = (const __u64 *)comp->ring;

	return &addrs[idx & comp->mask];
}

XDP_ALWAYS_INLINE struct xdp_desc *xsk_ring_prod__tx_desc(struct xsk_ring_prod *tx,
							  __u32 idx)
{
	struct xdp_desc *descs = (struct xdp_desc *)tx->ring;

	return &descs[idx & tx->mask];
}

XDP_ALWAYS_INLINE const struct xdp_desc *
xsk_ring_cons__rx_desc(const struct xsk_ring_cons *rx, __u32 idx)
{
	const struct xdp_desc *descs = (const struct xdp_desc *)rx->ring;

	return &descs[idx & rx->mask];
}

XDP_ALWAYS_INLINE int xsk_ring_prod__needs_wakeup(const struct xsk_ring_prod *r)
{
	return *r->flags & XDP_RING_NEED_WAKEUP;
}

XDP_ALWAYS_INLINE __u32 xsk_prod_nb_free(struct xsk_ring_prod *r, __u32 nb)
{
	__u32 free_entries = r->cached_cons - r->cached_prod;

	if (free_entries >= nb)
		return free_entries;

	/* Refresh the local tail pointer.
	 * cached_cons is r->size bigger than the real consumer pointer so
	 * that this addition can be avoided in the more frequently
	 * executed code that computs free_entries in the beginning of
	 * this function. Without this optimization it whould have been
	 * free_entries = r->cached_cons - r->cached_prod + r->size
	 */
	r->cached_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
	r->cached_cons += r->size;

	return r->cached_cons - r->cached_prod;
}

XDP_ALWAYS_INLINE __u32 xsk_cons_nb_avail(struct xsk_ring_cons *r, __u32 nb)
{
	__u32 entries = r->cached_prod - r->cached_cons;

	if (entries == 0) {
		r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
		entries = r->cached_prod - r->cached_cons;
	}

	return (entries > nb) ? nb : entries;
}

XDP_ALWAYS_INLINE __u32 xsk_ring_prod__reserve(struct xsk_ring_prod *prod, __u32 nb, __u32 *idx)
{
	if (xsk_prod_nb_free(prod, nb) < nb)
		return 0;

	*idx = prod->cached_prod;
	prod->cached_prod += nb;

	return nb;
}

XDP_ALWAYS_INLINE void xsk_ring_prod__submit(struct xsk_ring_prod *prod, __u32 nb)
{
	/* Make sure everything has been written to the ring before indicating
	 * this to the kernel by writing the producer pointer.
	 */
	__atomic_store_n(prod->producer, *prod->producer + nb, __ATOMIC_RELEASE);
}

XDP_ALWAYS_INLINE __u32 xsk_ring_cons__peek(struct xsk_ring_cons *cons, __u32 nb, __u32 *idx)
{
	__u32 entries = xsk_cons_nb_avail(cons, nb);

	if (entries > 0) {
		*idx = cons->cached_cons;
		cons->cached_cons += entries;
	}

	return entries;
}

XDP_ALWAYS_INLINE void xsk_ring_cons__cancel(struct xsk_ring_cons *cons, __u32 nb)
{
	cons->cached_cons -= nb;
}

XDP_ALWAYS_INLINE void xsk_ring_cons__release(struct xsk_ring_cons *cons, __u32 nb)
{
	/* Make sure data has been read before indicating we are done
	 * with the entries by updating the consumer pointer.
	 */
	__atomic_store_n(cons->consumer, *cons->consumer + nb, __ATOMIC_RELEASE);
}

XDP_ALWAYS_INLINE void *xsk_umem__get_data(void *umem_area, __u64 addr)
{
	return &((char *)umem_area)[addr];
}

XDP_ALWAYS_INLINE __u64 xsk_umem__extract_addr(__u64 addr)
{
	return addr & XSK_UNALIGNED_BUF_ADDR_MASK;
}

XDP_ALWAYS_INLINE __u64 xsk_umem__extract_offset(__u64 addr)
{
	return addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT;
}

XDP_ALWAYS_INLINE __u64 xsk_umem__add_offset_to_addr(__u64 addr)
{
	return xsk_umem__extract_addr(addr) + xsk_umem__extract_offset(addr);
}

int xsk_umem__fd(const struct xsk_umem *umem);
int xsk_socket__fd(const struct xsk_socket *xsk);

#define XSK_RING_CONS__DEFAULT_NUM_DESCS      2048
#define XSK_RING_PROD__DEFAULT_NUM_DESCS      2048
#define XSK_UMEM__DEFAULT_FRAME_SHIFT    12 /* 4096 bytes */
#define XSK_UMEM__DEFAULT_FRAME_SIZE     (1 << XSK_UMEM__DEFAULT_FRAME_SHIFT)
#define XSK_UMEM__DEFAULT_FRAME_HEADROOM 0
#define XSK_UMEM__DEFAULT_FLAGS 0
#define XSK_UMEM__DEFAULT_TX_METADATA_LEN 0

struct xsk_umem_config {
	__u32 fill_size;
	__u32 comp_size;
	__u32 frame_size;
	__u32 frame_headroom;
	__u32 flags;
};

/* The following fields are optional:
 * 
 * @fd, @size, @fill_size, @comp_size, @frame_size, @frame_headroom,
 * @flags, @tx_metadata_len
 *  If @fd is unset, a new sockfd will be created.
 *  If @size is unset, @umem_area must be page-aligned.
 *  If the remaining fields are unset, they will be set to 
 *  default value (see `xsk_set_umem_config()`).
 * 
 * Except for the fields mentioned above, no field can be set.
 */
struct xsk_umem_opts {
	size_t sz;
	int fd;
	__u64 size;
	__u32 fill_size;
	__u32 comp_size;
	__u32 frame_size;
	__u32 frame_headroom;
	__u32 flags;
	__u32 tx_metadata_len;
	size_t :0;
};
#define xsk_umem_opts__last_field tx_metadata_len

int xsk_setup_xdp_prog(int ifindex, int *xsks_map_fd);
int xsk_socket__update_xskmap(struct xsk_socket *xsk, int xsks_map_fd);

/* Flags for the libbpf_flags field.
 * We still call this field libbpf_flags for compatibility reasons.
 */
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1 << 0)
#define XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD (1 << 0)

struct xsk_socket_config {
	__u32 rx_size;
	__u32 tx_size;
	union {
		__u32 libbpf_flags;
		__u32 libxdp_flags;
	};
	__u32 xdp_flags;
	__u16 bind_flags;
};

/* 
 * The following fields should not be NULL at the same time:
 *
 * @rx, @tx
 *  At least one traffic direction should be assigned for an xsk.
 * 
 * The following fields are optional:
 * 
 * @fill, @comp, @rx_size, @tx_size, @libxdp_flags, @xdp_flags,
 * @bind_flags
 *  If @fill and @comp are both unset, they will be set to umem's
 *  fill_save and comp_save respectively. Note that it is invalid
 *  to set only one of them.
 *  If the remaining fields are unset, they will be set to 
 *  default value (see `xsk_set_xdp_socket_config()`).
 * 
 * Except for the fields mentioned above, no field can be set.
 */
struct xsk_socket_opts {
	size_t sz;
	struct xsk_ring_cons *rx;
	struct xsk_ring_prod *tx;
	struct xsk_ring_prod *fill;
	struct xsk_ring_cons *comp;
	__u32 rx_size;
	__u32 tx_size;
	__u32 libxdp_flags;
	__u32 xdp_flags;
	__u16 bind_flags;
	size_t :0;
};
#define xsk_socket_opts__last_field bind_flags

/* Set config to NULL to get the default configuration. */
int xsk_umem__create(struct xsk_umem **umem,
		     void *umem_area, __u64 size,
		     struct xsk_ring_prod *fill,
		     struct xsk_ring_cons *comp,
		     const struct xsk_umem_config *config);
int xsk_umem__create_with_fd(struct xsk_umem **umem,
			     int fd, void *umem_area, __u64 size,
			     struct xsk_ring_prod *fill,
			     struct xsk_ring_cons *comp,
			     const struct xsk_umem_config *config);
/* Newer version to create umem by opts, recommended to use. */
struct xsk_umem *xsk_umem__create_opts(void *umem_area,
				       struct xsk_ring_prod *fill,
				       struct xsk_ring_cons *comp,
				       struct xsk_umem_opts *opts);

int xsk_socket__create(struct xsk_socket **xsk,
		       const char *ifname, __u32 queue_id,
		       struct xsk_umem *umem,
		       struct xsk_ring_cons *rx,
		       struct xsk_ring_prod *tx,
		       const struct xsk_socket_config *config);
int xsk_socket__create_shared(struct xsk_socket **xsk_ptr,
			      const char *ifname,
			      __u32 queue_id, struct xsk_umem *umem,
			      struct xsk_ring_cons *rx,
			      struct xsk_ring_prod *tx,
			      struct xsk_ring_prod *fill,
			      struct xsk_ring_cons *comp,
			      const struct xsk_socket_config *config);
/* Newer version to create xsk by opts, recommended to use. */				  
struct xsk_socket *xsk_socket__create_opts(const char *ifname,
					   __u32 queue_id,
					   struct xsk_umem *umem,
					   struct xsk_socket_opts *opts);		  

/* Returns 0 for success and -EBUSY if the umem is still in use. */
int xsk_umem__delete(struct xsk_umem *umem);
void xsk_socket__delete(struct xsk_socket *xsk);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBBPF_XSK_H */

/* For new functions post libbpf */
#ifndef __LIBXDP_XSK_H
#define __LIBXDP_XSK_H

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBXDP_XSK_H */
