// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * AF_XDP user-space access library.
 *
 * Copyright(c) 2018 - 2021 Intel Corporation.
 *
 * Author(s): Magnus Karlsson <magnus.karlsson@intel.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/err.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <linux/list.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <xdp/xsk.h>

#include "libxdp_internal.h"
#include "util.h"

#ifndef SOL_XDP
 #define SOL_XDP 283
#endif

#ifndef AF_XDP
 #define AF_XDP 44
#endif

#ifndef PF_XDP
 #define PF_XDP AF_XDP
#endif

struct xsk_umem {
	struct xsk_ring_prod *fill_save;
	struct xsk_ring_cons *comp_save;
	char *umem_area;
	struct xsk_umem_config config;
	int fd;
	int refcount;
	struct list_head ctx_list;
};

struct xsk_ctx {
	struct xsk_ring_prod *fill;
	struct xsk_ring_cons *comp;
	__u32 queue_id;
	struct xsk_umem *umem;
	int refcount;
	int ifindex;
	struct list_head list;
	struct xdp_program *xdp_prog;
	int prog_fd;
	int xsks_map_fd;
	char ifname[IFNAMSIZ];
};

struct xsk_socket {
	struct xsk_ring_cons *rx;
	struct xsk_ring_prod *tx;
	__u64 outstanding_tx;
	struct xsk_ctx *ctx;
	struct xsk_socket_config config;
	int fd;
};

struct xsk_nl_info {
	bool xdp_prog_attached;
	int ifindex;
	int fd;
};

/* Up until and including Linux 5.3 */
struct xdp_ring_offset_v1 {
	__u64 producer;
	__u64 consumer;
	__u64 desc;
};

/* Up until and including Linux 5.3 */
struct xdp_mmap_offsets_v1 {
	struct xdp_ring_offset_v1 rx;
	struct xdp_ring_offset_v1 tx;
	struct xdp_ring_offset_v1 fr;
	struct xdp_ring_offset_v1 cr;
};

int xsk_umem__fd(const struct xsk_umem *umem)
{
	return umem ? umem->fd : -EINVAL;
}

int xsk_socket__fd(const struct xsk_socket *xsk)
{
	return xsk ? xsk->fd : -EINVAL;
}

static bool xsk_page_aligned(void *buffer)
{
	unsigned long addr = (unsigned long)buffer;

	return !(addr & (getpagesize() - 1));
}

static void xsk_set_umem_config(struct xsk_umem_config *cfg,
				const struct xsk_umem_config *usr_cfg)
{
	if (!usr_cfg) {
		cfg->fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
		cfg->comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
		cfg->frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
		cfg->frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
		cfg->flags = XSK_UMEM__DEFAULT_FLAGS;
		return;
	}

	cfg->fill_size = usr_cfg->fill_size;
	cfg->comp_size = usr_cfg->comp_size;
	cfg->frame_size = usr_cfg->frame_size;
	cfg->frame_headroom = usr_cfg->frame_headroom;
	cfg->flags = usr_cfg->flags;
}

static int xsk_set_xdp_socket_config(struct xsk_socket_config *cfg,
				     const struct xsk_socket_config *usr_cfg)
{
	if (!usr_cfg) {
		cfg->rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
		cfg->tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
		cfg->libbpf_flags = 0;
		cfg->xdp_flags = 0;
		cfg->bind_flags = 0;
		return 0;
	}

	if (usr_cfg->libbpf_flags & ~XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD)
		return -EINVAL;

	cfg->rx_size = usr_cfg->rx_size;
	cfg->tx_size = usr_cfg->tx_size;
	cfg->libbpf_flags = usr_cfg->libbpf_flags;
	cfg->xdp_flags = usr_cfg->xdp_flags;
	cfg->bind_flags = usr_cfg->bind_flags;

	return 0;
}

static void xsk_mmap_offsets_v1(struct xdp_mmap_offsets *off)
{
	struct xdp_mmap_offsets_v1 off_v1;

	/* getsockopt on a kernel <= 5.3 has no flags fields.
	 * Copy over the offsets to the correct places in the >=5.4 format
	 * and put the flags where they would have been on that kernel.
	 */
	memcpy(&off_v1, off, sizeof(off_v1));

	off->rx.producer = off_v1.rx.producer;
	off->rx.consumer = off_v1.rx.consumer;
	off->rx.desc = off_v1.rx.desc;
	off->rx.flags = off_v1.rx.consumer + sizeof(__u32);

	off->tx.producer = off_v1.tx.producer;
	off->tx.consumer = off_v1.tx.consumer;
	off->tx.desc = off_v1.tx.desc;
	off->tx.flags = off_v1.tx.consumer + sizeof(__u32);

	off->fr.producer = off_v1.fr.producer;
	off->fr.consumer = off_v1.fr.consumer;
	off->fr.desc = off_v1.fr.desc;
	off->fr.flags = off_v1.fr.consumer + sizeof(__u32);

	off->cr.producer = off_v1.cr.producer;
	off->cr.consumer = off_v1.cr.consumer;
	off->cr.desc = off_v1.cr.desc;
	off->cr.flags = off_v1.cr.consumer + sizeof(__u32);
}

static int xsk_get_mmap_offsets(int fd, struct xdp_mmap_offsets *off)
{
	socklen_t optlen;
	int err;

	optlen = sizeof(*off);
	err = getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, off, &optlen);
	if (err)
		return err;

	if (optlen == sizeof(*off))
		return 0;

	if (optlen == sizeof(struct xdp_mmap_offsets_v1)) {
		xsk_mmap_offsets_v1(off);
		return 0;
	}

	return -EINVAL;
}

static int xsk_create_umem_rings(struct xsk_umem *umem, int fd,
				 struct xsk_ring_prod *fill,
				 struct xsk_ring_cons *comp)
{
	struct xdp_mmap_offsets off;
	void *map;
	int err;

	err = setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING,
			 &umem->config.fill_size,
			 sizeof(umem->config.fill_size));
	if (err)
		return -errno;

	err = setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
			 &umem->config.comp_size,
			 sizeof(umem->config.comp_size));
	if (err)
		return -errno;

	err = xsk_get_mmap_offsets(fd, &off);
	if (err)
		return -errno;

	map = mmap(NULL, off.fr.desc + umem->config.fill_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		   XDP_UMEM_PGOFF_FILL_RING);
	if (map == MAP_FAILED)
		return -errno;

	fill->mask = umem->config.fill_size - 1;
	fill->size = umem->config.fill_size;
	fill->producer = map + off.fr.producer;
	fill->consumer = map + off.fr.consumer;
	fill->flags = map + off.fr.flags;
	fill->ring = map + off.fr.desc;
	fill->cached_cons = umem->config.fill_size;

	map = mmap(NULL, off.cr.desc + umem->config.comp_size * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
		   XDP_UMEM_PGOFF_COMPLETION_RING);
	if (map == MAP_FAILED) {
		err = -errno;
		goto out_mmap;
	}

	comp->mask = umem->config.comp_size - 1;
	comp->size = umem->config.comp_size;
	comp->producer = map + off.cr.producer;
	comp->consumer = map + off.cr.consumer;
	comp->flags = map + off.cr.flags;
	comp->ring = map + off.cr.desc;

	return 0;

out_mmap:
	munmap(map, off.fr.desc + umem->config.fill_size * sizeof(__u64));
	return err;
}

int xsk_umem__create(struct xsk_umem **umem_ptr, void *umem_area,
		     __u64 size, struct xsk_ring_prod *fill,
		     struct xsk_ring_cons *comp,
		     const struct xsk_umem_config *usr_config)
{
	struct xdp_umem_reg mr;
	struct xsk_umem *umem;
	int err;

	if (!umem_area || !umem_ptr || !fill || !comp)
		return -EFAULT;
	if (!size && !xsk_page_aligned(umem_area))
		return -EINVAL;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return -ENOMEM;

	umem->fd = socket(AF_XDP, SOCK_RAW, 0);
	if (umem->fd < 0) {
		err = -errno;
		goto out_umem_alloc;
	}

	umem->umem_area = umem_area;
	INIT_LIST_HEAD(&umem->ctx_list);
	xsk_set_umem_config(&umem->config, usr_config);

	memset(&mr, 0, sizeof(mr));
	mr.addr = (uintptr_t)umem_area;
	mr.len = size;
	mr.chunk_size = umem->config.frame_size;
	mr.headroom = umem->config.frame_headroom;
	mr.flags = umem->config.flags;

	err = setsockopt(umem->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
	if (err) {
		err = -errno;
		goto out_socket;
	}

	err = xsk_create_umem_rings(umem, umem->fd, fill, comp);
	if (err)
		goto out_socket;

	umem->fill_save = fill;
	umem->comp_save = comp;
	*umem_ptr = umem;
	return 0;

out_socket:
	close(umem->fd);
out_umem_alloc:
	free(umem);
	return err;
}

struct xsk_umem_config_v1 {
	__u32 fill_size;
	__u32 comp_size;
	__u32 frame_size;
	__u32 frame_headroom;
};

static int xsk_get_max_queues(struct xsk_socket *xsk)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct xsk_ctx *ctx = xsk->ctx;
	struct ifreq ifr = {};
	int fd, err, ret;

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ctx->ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		ret = -errno;
		goto out;
	}

	if (err) {
		/* If the device says it has no channels, then all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		ret = 1;
	} else {
		/* Take the max of rx, tx, combined. Drivers return
		 * the number of channels in different ways.
		 */
		ret = max(channels.max_rx, channels.max_tx);
		ret = max(ret, (int)channels.max_combined);
	}

out:
	close(fd);
	return ret;
}

static int xsk_size_map(struct xsk_socket *xsk)
{
	struct xsk_ctx *ctx = xsk->ctx;
	struct bpf_object *bpf_obj = xdp_program__bpf_obj(ctx->xdp_prog);
	struct bpf_map *map;
	int max_queues;
	int err;

	max_queues = xsk_get_max_queues(xsk);
	if (max_queues < 0)
		return max_queues;

	map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
	if (!map)
		return -ENOENT;

	ctx->xsks_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xsks_map");
	if (ctx->xsks_map_fd < 0)
		return ctx->xsks_map_fd;

	err = bpf_map__resize(map, max_queues);
	if (err)
		return err;

	return 0;
}

static void xsk_delete_map_entry(struct xsk_socket *xsk)
{
	struct xsk_ctx *ctx = xsk->ctx;

	bpf_map_delete_elem(ctx->xsks_map_fd, &ctx->queue_id);
	close(ctx->xsks_map_fd);
}

static int xsk_lookup_bpf_map(struct xsk_socket *xsk)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	struct xsk_ctx *ctx = xsk->ctx;
	struct bpf_map_info map_info;
	int fd, err;

	err = bpf_obj_get_info_by_fd(ctx->prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(ctx->prog_fd, &prog_info, &prog_len);
	if (err)
		goto out_map_ids;

	ctx->xsks_map_fd = -1;

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strcmp(map_info.name, "xsks_map")) {
			ctx->xsks_map_fd = fd;
			continue;
		}

		close(fd);
	}

	err = 0;
	if (ctx->xsks_map_fd == -1)
		err = -ENOENT;

out_map_ids:
	free(map_ids);
	return err;
}

static int xsk_add_map_entry(struct xsk_socket *xsk)
{
	struct xsk_ctx *ctx = xsk->ctx;

	return bpf_map_update_elem(ctx->xsks_map_fd, &ctx->queue_id,
				   &xsk->fd, 0);
}

static int xsk_create_xsk_struct(int ifindex, struct xsk_socket *xsk)
{
	char ifname[IFNAMSIZ];
	struct xsk_ctx *ctx;
	char *interface;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	interface = if_indextoname(ifindex, &ifname[0]);
	if (!interface) {
		free(ctx);
		return -errno;
	}

	ctx->ifindex = ifindex;
	memcpy(ctx->ifname, ifname, IFNAMSIZ -1);
	ctx->ifname[IFNAMSIZ - 1] = 0;

	xsk->ctx = ctx;

	return 0;
}

static enum xdp_attach_mode xsk_convert_xdp_flags(__u32 xdp_flags)
{
	if (xdp_flags & XDP_FLAGS_REPLACE)
		pr_warn("XDP_FLAGS_REPLACE not supported by libxdp.\n");

	if (xdp_flags & XDP_FLAGS_SKB_MODE)
		return XDP_MODE_SKB;
	if (xdp_flags & XDP_FLAGS_DRV_MODE)
		return XDP_MODE_NATIVE;
	if (xdp_flags & XDP_FLAGS_HW_MODE)
		return XDP_MODE_HW;

	return XDP_MODE_UNSPEC;
}

static int xsk_lookup_program(struct xsk_socket *xsk)
{
	struct xdp_multiprog *multi_prog;
	struct xdp_program *prog = NULL;
	struct xsk_ctx *ctx = xsk->ctx;

	multi_prog = xdp_multiprog__get_from_ifindex(ctx->ifindex);
	if (!multi_prog)
		return -1;

	while ((prog = xdp_multiprog__next_prog(prog, multi_prog)))
		if (!strcmp(xdp_program__name(prog), "xsk_def_prog"))
			break;

	if (!prog)
		return -1;
	return xdp_program__fd(prog);
}

static int __xsk_setup_xdp_prog(struct xsk_socket *xsk, int *xsks_map_fd)
{
	struct xsk_ctx *ctx = xsk->ctx;
	int prog_fd, err;

	prog_fd = xsk_lookup_program(xsk);

	if (prog_fd < 0) {
		ctx->xdp_prog = xdp_program__find_file("xsk_def_xdp_prog.o", NULL, NULL);
		if (IS_ERR(ctx->xdp_prog))
			return PTR_ERR(ctx->xdp_prog);

		err = xsk_size_map(xsk);
		if (err)
			goto err_prog_load;

		err = xdp_program__attach(ctx->xdp_prog, ctx->ifindex,
					  xsk_convert_xdp_flags(xsk->config.xdp_flags), 0);
		if (err)
			goto err_prog_load;
		ctx->prog_fd = xdp_program__fd(ctx->xdp_prog);
	} else {
		ctx->prog_fd = prog_fd;
		if (ctx->prog_fd < 0)
			return -errno;
		err = xsk_lookup_bpf_map(xsk);
		if (err) {
			close(ctx->prog_fd);
			return err;
		}
	}

	if (xsk->rx) {
		err = xsk_add_map_entry(xsk);
		if (err) {
			if (prog_fd < 0) {
				goto err_detach;
			} else {
				close(ctx->prog_fd);
				return err;
			}
		}
	}
	if (xsks_map_fd)
		*xsks_map_fd = ctx->xsks_map_fd;

	return 0;

err_detach:
	xdp_program__detach(ctx->xdp_prog, ctx->ifindex,
			    xsk_convert_xdp_flags(xsk->config.xdp_flags), 0);
err_prog_load:
	xdp_program__close(ctx->xdp_prog);
	return err;
}

static struct xsk_ctx *xsk_get_ctx(struct xsk_umem *umem, int ifindex,
				   __u32 queue_id)
{
	struct xsk_ctx *ctx;

	if (list_empty(&umem->ctx_list))
		return NULL;

	list_for_each_entry(ctx, &umem->ctx_list, list) {
		if (ctx->ifindex == ifindex && ctx->queue_id == queue_id) {
			ctx->refcount++;
			return ctx;
		}
	}

	return NULL;
}

static void xsk_put_ctx(struct xsk_ctx *ctx)
{
	struct xsk_umem *umem = ctx->umem;
	struct xdp_mmap_offsets off;
	int err;

	if (--ctx->refcount == 0) {
		err = xsk_get_mmap_offsets(umem->fd, &off);
		if (!err) {
			munmap(ctx->fill->ring - off.fr.desc,
			       off.fr.desc + umem->config.fill_size *
			       sizeof(__u64));
			munmap(ctx->comp->ring - off.cr.desc,
			       off.cr.desc + umem->config.comp_size *
			       sizeof(__u64));
		}

		list_del(&ctx->list);
		free(ctx);
	}
}

static struct xsk_ctx *xsk_create_ctx(struct xsk_socket *xsk,
				      struct xsk_umem *umem, int ifindex,
				      const char *ifname, __u32 queue_id,
				      struct xsk_ring_prod *fill,
				      struct xsk_ring_cons *comp)
{
	struct xsk_ctx *ctx;
	int err;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (!umem->fill_save) {
		err = xsk_create_umem_rings(umem, xsk->fd, fill, comp);
		if (err) {
			free(ctx);
			return NULL;
		}
	} else if (umem->fill_save != fill || umem->comp_save != comp) {
		/* Copy over rings to new structs. */
		memcpy(fill, umem->fill_save, sizeof(*fill));
		memcpy(comp, umem->comp_save, sizeof(*comp));
	}

	ctx->ifindex = ifindex;
	ctx->refcount = 1;
	ctx->umem = umem;
	ctx->queue_id = queue_id;
	memcpy(ctx->ifname, ifname, IFNAMSIZ - 1);
	ctx->ifname[IFNAMSIZ - 1] = '\0';

	umem->fill_save = NULL;
	umem->comp_save = NULL;
	ctx->fill = fill;
	ctx->comp = comp;
	list_add(&ctx->list, &umem->ctx_list);
	return ctx;
}

static void xsk_destroy_xsk_struct(struct xsk_socket *xsk)
{
	free(xsk->ctx);
	free(xsk);
}

int xsk_socket__update_xskmap(struct xsk_socket *xsk, int fd)
{
	xsk->ctx->xsks_map_fd = fd;
	return xsk_add_map_entry(xsk);
}

int xsk_setup_xdp_prog(int ifindex, int *xsks_map_fd)
{
	struct xsk_socket *xsk;
	int res;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return -ENOMEM;

	res = xsk_create_xsk_struct(ifindex, xsk);
	if (res) {
		free(xsk);
		return -EINVAL;
	}

	res = __xsk_setup_xdp_prog(xsk, xsks_map_fd);

	xsk_destroy_xsk_struct(xsk);

	return res;
}

int xsk_socket__create_shared(struct xsk_socket **xsk_ptr,
			      const char *ifname,
			      __u32 queue_id, struct xsk_umem *umem,
			      struct xsk_ring_cons *rx,
			      struct xsk_ring_prod *tx,
			      struct xsk_ring_prod *fill,
			      struct xsk_ring_cons *comp,
			      const struct xsk_socket_config *usr_config)
{
	void *rx_map = NULL, *tx_map = NULL;
	struct sockaddr_xdp sxdp = {};
	struct xdp_mmap_offsets off;
	struct xsk_socket *xsk;
	struct xsk_ctx *ctx;
	int err, ifindex;

	if (!umem || !xsk_ptr || !(rx || tx))
		return -EFAULT;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return -ENOMEM;

	err = xsk_set_xdp_socket_config(&xsk->config, usr_config);
	if (err)
		goto out_xsk_alloc;

	xsk->outstanding_tx = 0;
	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		err = -errno;
		goto out_xsk_alloc;
	}

	if (umem->refcount++ > 0) {
		xsk->fd = socket(AF_XDP, SOCK_RAW, 0);
		if (xsk->fd < 0) {
			err = -errno;
			goto out_xsk_alloc;
		}
	} else {
		xsk->fd = umem->fd;
	}

	ctx = xsk_get_ctx(umem, ifindex, queue_id);
	if (!ctx) {
		if (!fill || !comp) {
			err = -EFAULT;
			goto out_socket;
		}

		ctx = xsk_create_ctx(xsk, umem, ifindex, ifname, queue_id,
				     fill, comp);
		if (!ctx) {
			err = -ENOMEM;
			goto out_socket;
		}
	}
	xsk->ctx = ctx;

	if (rx) {
		err = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING,
				 &xsk->config.rx_size,
				 sizeof(xsk->config.rx_size));
		if (err) {
			err = -errno;
			goto out_put_ctx;
		}
	}
	if (tx) {
		err = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING,
				 &xsk->config.tx_size,
				 sizeof(xsk->config.tx_size));
		if (err) {
			err = -errno;
			goto out_put_ctx;
		}
	}

	err = xsk_get_mmap_offsets(xsk->fd, &off);
	if (err) {
		err = -errno;
		goto out_put_ctx;
	}

	if (rx) {
		rx_map = mmap(NULL, off.rx.desc +
			      xsk->config.rx_size * sizeof(struct xdp_desc),
			      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
			      xsk->fd, XDP_PGOFF_RX_RING);
		if (rx_map == MAP_FAILED) {
			err = -errno;
			goto out_put_ctx;
		}

		rx->mask = xsk->config.rx_size - 1;
		rx->size = xsk->config.rx_size;
		rx->producer = rx_map + off.rx.producer;
		rx->consumer = rx_map + off.rx.consumer;
		rx->flags = rx_map + off.rx.flags;
		rx->ring = rx_map + off.rx.desc;
		rx->cached_prod = *rx->producer;
		rx->cached_cons = *rx->consumer;
	}
	xsk->rx = rx;

	if (tx) {
		tx_map = mmap(NULL, off.tx.desc +
			      xsk->config.tx_size * sizeof(struct xdp_desc),
			      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
			      xsk->fd, XDP_PGOFF_TX_RING);
		if (tx_map == MAP_FAILED) {
			err = -errno;
			goto out_mmap_rx;
		}

		tx->mask = xsk->config.tx_size - 1;
		tx->size = xsk->config.tx_size;
		tx->producer = tx_map + off.tx.producer;
		tx->consumer = tx_map + off.tx.consumer;
		tx->flags = tx_map + off.tx.flags;
		tx->ring = tx_map + off.tx.desc;
		tx->cached_prod = *tx->producer;
		/* cached_cons is r->size bigger than the real consumer pointer
		 * See xsk_prod_nb_free
		 */
		tx->cached_cons = *tx->consumer + xsk->config.tx_size;
	}
	xsk->tx = tx;

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_ifindex = ctx->ifindex;
	sxdp.sxdp_queue_id = ctx->queue_id;
	if (umem->refcount > 1) {
		sxdp.sxdp_flags |= XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = umem->fd;
	} else {
		sxdp.sxdp_flags = xsk->config.bind_flags;
	}

	err = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
	if (err) {
		err = -errno;
		goto out_mmap_tx;
	}

	ctx->prog_fd = -1;

	if (!(xsk->config.libbpf_flags & XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD)) {
		err = __xsk_setup_xdp_prog(xsk, NULL);
		if (err)
			goto out_mmap_tx;
	}

	*xsk_ptr = xsk;
	return 0;

out_mmap_tx:
	if (tx)
		munmap(tx_map, off.tx.desc +
		       xsk->config.tx_size * sizeof(struct xdp_desc));
out_mmap_rx:
	if (rx)
		munmap(rx_map, off.rx.desc +
		       xsk->config.rx_size * sizeof(struct xdp_desc));
out_put_ctx:
	xsk_put_ctx(ctx);
out_socket:
	if (--umem->refcount)
		close(xsk->fd);
out_xsk_alloc:
	free(xsk);
	return err;
}

int xsk_socket__create(struct xsk_socket **xsk_ptr, const char *ifname,
		       __u32 queue_id, struct xsk_umem *umem,
		       struct xsk_ring_cons *rx, struct xsk_ring_prod *tx,
		       const struct xsk_socket_config *usr_config)
{
	return xsk_socket__create_shared(xsk_ptr, ifname, queue_id, umem,
					 rx, tx, umem->fill_save,
					 umem->comp_save, usr_config);
}

int xsk_umem__delete(struct xsk_umem *umem)
{
	if (!umem)
		return 0;

	if (umem->refcount)
		return -EBUSY;

	close(umem->fd);
	free(umem);

	return 0;
}

void xsk_socket__delete(struct xsk_socket *xsk)
{
	size_t desc_sz = sizeof(struct xdp_desc);
	struct xdp_mmap_offsets off;
	struct xsk_umem *umem;
	struct xsk_ctx *ctx;
	int err;

	if (!xsk)
		return;

	ctx = xsk->ctx;
	umem = ctx->umem;
	if (ctx->prog_fd != -1) {
		xsk_delete_map_entry(xsk);
		if (ctx->xdp_prog)
			xdp_program__close(ctx->xdp_prog);
		else
			close(ctx->prog_fd);
	}

	err = xsk_get_mmap_offsets(xsk->fd, &off);
	if (!err) {
		if (xsk->rx) {
			munmap(xsk->rx->ring - off.rx.desc,
			       off.rx.desc + xsk->config.rx_size * desc_sz);
		}
		if (xsk->tx) {
			munmap(xsk->tx->ring - off.tx.desc,
			       off.tx.desc + xsk->config.tx_size * desc_sz);
		}
	}

	xsk_put_ctx(ctx);

	umem->refcount--;
	/* Do not close an fd that also has an associated umem connected
	 * to it.
	 */
	if (xsk->fd != umem->fd)
		close(xsk->fd);
	free(xsk);
}
