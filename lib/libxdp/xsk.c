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
#include <dirent.h>
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
#include "xsk_def_xdp_prog.h"
#include "bpf_instr.h"

#ifndef SOL_XDP
 #define SOL_XDP 283
#endif

#ifndef AF_XDP
 #define AF_XDP 44
#endif

#ifndef PF_XDP
 #define PF_XDP AF_XDP
#endif

#ifndef SO_NETNS_COOKIE
 #define SO_NETNS_COOKIE 71
#endif

#define INIT_NS 1

struct xsk_umem {
	struct xsk_ring_prod *fill_save;
	struct xsk_ring_cons *comp_save;
	char *umem_area;
	struct xsk_umem_config config;
	int fd;
	int refcount;
	struct list_head ctx_list;
	bool rx_ring_setup_done;
	bool tx_ring_setup_done;
};

struct xsk_ctx {
	struct xsk_ring_prod *fill;
	struct xsk_ring_cons *comp;
	struct xsk_umem *umem;
	__u32 queue_id;
	int refcount;
	int ifindex;
	__u64 netns_cookie;
	int xsks_map_fd;
	struct list_head list;
	struct xdp_program *xdp_prog;
	int refcnt_map_fd;
	char ifname[IFNAMSIZ];
};

struct xsk_socket {
	struct xsk_ring_cons *rx;
	struct xsk_ring_prod *tx;
	struct xsk_ctx *ctx;
	struct xsk_socket_config config;
	int fd;
};

struct xsk_nl_info {
	int ifindex;
	int fd;
	bool xdp_prog_attached;
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

/* Export all inline helpers as symbols for use by language bindings. */
extern inline __u64 *xsk_ring_prod__fill_addr(struct xsk_ring_prod *fill,
					      __u32 idx);
extern inline const __u64 *
xsk_ring_cons__comp_addr(const struct xsk_ring_cons *comp, __u32 idx);
extern inline struct xdp_desc *xsk_ring_prod__tx_desc(struct xsk_ring_prod *tx,
						      __u32 idx);
extern inline const struct xdp_desc *
xsk_ring_cons__rx_desc(const struct xsk_ring_cons *rx, __u32 idx);
extern inline int xsk_ring_prod__needs_wakeup(const struct xsk_ring_prod *r);
extern inline __u32 xsk_prod_nb_free(struct xsk_ring_prod *r, __u32 nb);
extern inline __u32 xsk_cons_nb_avail(struct xsk_ring_cons *r, __u32 nb);
extern inline __u32 xsk_ring_prod__reserve(struct xsk_ring_prod *prod, __u32 nb,
					   __u32 *idx);
extern inline void xsk_ring_prod__submit(struct xsk_ring_prod *prod, __u32 nb);
extern inline __u32 xsk_ring_cons__peek(struct xsk_ring_cons *cons, __u32 nb,
					__u32 *idx);
extern inline void xsk_ring_cons__cancel(struct xsk_ring_cons *cons, __u32 nb);
extern inline void xsk_ring_cons__release(struct xsk_ring_cons *cons, __u32 nb);
extern inline void *xsk_umem__get_data(void *umem_area, __u64 addr);
extern inline __u64 xsk_umem__extract_addr(__u64 addr);
extern inline __u64 xsk_umem__extract_offset(__u64 addr);
extern inline __u64 xsk_umem__add_offset_to_addr(__u64 addr);

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
				const struct xsk_umem_opts *opts)
{
	cfg->fill_size = OPTS_GET(opts, fill_size, 0) ?: XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg->comp_size = OPTS_GET(opts, comp_size, 0) ?: XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg->frame_size = OPTS_GET(opts, frame_size, 0) ?: XSK_UMEM__DEFAULT_FRAME_SIZE;
	cfg->frame_headroom = OPTS_GET(opts, frame_headroom, 0) ?: XSK_UMEM__DEFAULT_FRAME_HEADROOM;
	cfg->flags = OPTS_GET(opts, flags, 0) ?: XSK_UMEM__DEFAULT_FLAGS;
}

static int xsk_set_xdp_socket_config(struct xsk_socket_config *cfg,
				     const struct xsk_socket_opts *opts)
{
	__u32 libxdp_flags;

	libxdp_flags = OPTS_GET(opts, libxdp_flags, 0);
	if (libxdp_flags & ~XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD)
		return -EINVAL;

	cfg->rx_size = OPTS_GET(opts, rx_size, 0) ?: XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg->tx_size = OPTS_GET(opts, tx_size, 0) ?: XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg->libxdp_flags = libxdp_flags;
	cfg->xdp_flags = OPTS_GET(opts, xdp_flags, 0);
	cfg->bind_flags = OPTS_GET(opts, bind_flags, 0);

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

struct xsk_umem *xsk_umem__create_opts(void *umem_area,
				       struct xsk_ring_prod *fill,
				       struct xsk_ring_cons *comp,
				       struct xsk_umem_opts *opts) {
	struct xdp_umem_reg mr;
	struct xsk_umem *umem;
	int err, fd;
	__u64 size;
	
	if (!umem_area || !fill || !comp) {
		err = -EFAULT;
		goto err;
	}

	if (!OPTS_VALID(opts, xsk_umem_opts)) {
		err = -EINVAL;
		goto err;
	}
	fd = OPTS_GET(opts, fd, 0);
	size = OPTS_GET(opts, size, 0);
	
	if (!size && !xsk_page_aligned(umem_area)) {
		err = -EINVAL;
		goto err;
	}

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		err = -ENOMEM;
		goto err;
	}

	umem->fd = fd > 0 ? fd : socket(AF_XDP, SOCK_RAW, 0);
	if (umem->fd < 0) {
		err = -errno;
		goto out_umem_alloc;
	}

	umem->umem_area = umem_area;
	INIT_LIST_HEAD(&umem->ctx_list);
	xsk_set_umem_config(&umem->config, opts);

	memset(&mr, 0, sizeof(mr));
	mr.addr = (uintptr_t)umem_area;
	mr.len = size;
	mr.chunk_size = umem->config.frame_size;
	mr.headroom = umem->config.frame_headroom;
	mr.flags = umem->config.flags;
	mr.tx_metadata_len = OPTS_GET(opts, tx_metadata_len, XSK_UMEM__DEFAULT_TX_METADATA_LEN);
	
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
	return umem;
out_socket:
	close(umem->fd);
out_umem_alloc:
	free(umem);
err:
	return libxdp_err_ptr(err, true);
}

int xsk_umem__create_with_fd(struct xsk_umem **umem_ptr, int fd,
			     void *umem_area, __u64 size,
			     struct xsk_ring_prod *fill,
			     struct xsk_ring_cons *comp,
			     const struct xsk_umem_config *usr_config)
{
	struct xsk_umem *umem;

	if (!umem_ptr)
		return -EFAULT;

	DECLARE_LIBXDP_OPTS(xsk_umem_opts, opts,
		.fd = fd,
		.size = size,
	);
	if (usr_config) {
		opts.fill_size = usr_config->fill_size;
		opts.comp_size = usr_config->comp_size;
		opts.frame_size = usr_config->frame_size;
		opts.frame_headroom = usr_config->frame_headroom;
		opts.flags = usr_config->flags;
	}
	umem = xsk_umem__create_opts(umem_area, fill, comp, &opts);
	if (!umem)
		return -errno;
	
	*umem_ptr = umem;
	return 0;
}

int xsk_umem__create(struct xsk_umem **umem_ptr, void *umem_area,
		     __u64 size, struct xsk_ring_prod *fill,
		     struct xsk_ring_cons *comp,
		     const struct xsk_umem_config *usr_config)
{
	return xsk_umem__create_with_fd(umem_ptr, 0, umem_area, size,
					fill, comp, usr_config);
}

static int xsk_init_xsk_struct(struct xsk_socket *xsk, int ifindex)
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
	if (xdp_flags & ~XDP_FLAGS_MASK)
		pr_warn("XDP flag: 0x%x contains flags not supported by libxdp.\n", xdp_flags);

	if (xdp_flags & XDP_FLAGS_SKB_MODE)
		return XDP_MODE_SKB;
	if (xdp_flags & XDP_FLAGS_DRV_MODE)
		return XDP_MODE_NATIVE;
	if (xdp_flags & XDP_FLAGS_HW_MODE)
		return XDP_MODE_HW;

	return XDP_MODE_NATIVE;
}

#define MAX_DEV_QUEUE_PATH_LEN 64

static void xsk_get_queues_from_sysfs(const char* ifname, __u32 *rx, __u32 *tx) {
	char buf[MAX_DEV_QUEUE_PATH_LEN];
	struct dirent *entry;
	DIR *dir;
	int err;

	*rx = *tx = 0;

	err = try_snprintf(buf, MAX_DEV_QUEUE_PATH_LEN,
			"/sys/class/net/%s/queues/", ifname);
	if (err)
		return;

	dir = opendir(buf);
	if(dir == NULL)
		return;

	while((entry = readdir(dir))) {
		if (0 == strncmp(entry->d_name, "rx", 2))
			++*rx;

		if (0 == strncmp(entry->d_name, "tx", 2))
			++*tx;
	}

	closedir(dir);
}

static int xsk_get_max_queues(char *ifname)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
	struct ifreq ifr = {};
	int fd, err, ret;

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	ifr.ifr_data = (void *)&channels;
	memcpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err && errno != EOPNOTSUPP) {
		ret = -errno;
		goto out;
	}

	if (err) {
		/* If the device says it has no channels,
		 * try to get rx tx from sysfs, otherwise all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
		__u32 rx, tx;
		xsk_get_queues_from_sysfs(ifr.ifr_name, &rx, &tx);
		ret = max(max(rx, tx), 1);
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

static int xsk_size_map(struct xdp_program *xdp_prog, char *ifname)
{
	struct bpf_object *bpf_obj = xdp_program__bpf_obj(xdp_prog);
	struct bpf_map *map;
	int max_queues;
	int err;

	max_queues = xsk_get_max_queues(ifname);
	if (max_queues < 0)
		return max_queues;

	map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
	if (!map)
		return -ENOENT;

	err = bpf_map__set_max_entries(map, max_queues);
	if (err)
		return err;

	return 0;
}

static void xsk_delete_map_entry(int xsks_map_fd, __u32 queue_id)
{
	bpf_map_delete_elem(xsks_map_fd, &queue_id);
	close(xsks_map_fd);
}

static int xsk_lookup_map_by_filter(int prog_fd,
				    bool (*map_info_filter)(struct bpf_map_info *map_info))
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (map_info_filter(&map_info)) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}

static bool xsk_map_is_socket_map(struct bpf_map_info *map_info)
{
	return !strncmp(map_info->name, "xsks_map", sizeof(map_info->name)) &&
		map_info->key_size == 4 && map_info->value_size == 4;
}

static bool xsk_map_is_refcnt_map(struct bpf_map_info *map_info)
{
	/* In order to avoid confusing users with multiple identically named
	 * maps, libbpf names non-custom internal maps (.data, .bss, etc.)
	 * in an unexpected way, namely the first 8 characters of a bpf object
	 * name + a suffix signifying the internal map type,
	 * ex. "xdp_def_" + ".data".
	 */
	return !strncmp(map_info->name, "xsk_def_.data",
			sizeof(map_info->name)) &&
			map_info->value_size >= sizeof(int);
}

static int xsk_lookup_bpf_map(int prog_fd)
{
	return xsk_lookup_map_by_filter(prog_fd, &xsk_map_is_socket_map);
}

static int xsk_lookup_refcnt_map(int prog_fd, const char *xdp_filename)
{
	int map_fd = xsk_lookup_map_by_filter(prog_fd, &xsk_map_is_refcnt_map);

	if (map_fd >= 0)
		goto out;

	if (map_fd != -ENOENT) {
		pr_debug("Error getting refcount map: %s\n", strerror(-map_fd));
		goto out;
	}

	if (xdp_filename)
		pr_warn("Refcount was not found in %s or kernel does not support required features, so automatic program removal on unload is disabled\n",
			xdp_filename);
	else
		pr_warn("Another XSK socket was created by a version of libxdp that doesn't support program refcnt, so automatic program removal on unload is disabled.\n");
out:
	return map_fd;
}

#ifdef HAVE_LIBBPF_BPF_MAP_CREATE
/* bpf_map_create() and the new bpf_prog_create() were added at the same time -
 * however there's a naming conflict with another bpf_prog_load() function in
 * older versions of libbpf; to avoid hitting that we create our own wrapper
 * function for this one even with new libbpf versions.
 */
static int xsk_check_create_prog(struct bpf_insn *insns, size_t insns_cnt)
{
	return bpf_prog_load(BPF_PROG_TYPE_XDP, "testprog",
			     "GPL", insns, insns_cnt, NULL);
}
#else
static int bpf_map_create(enum bpf_map_type map_type,
			  __unused const char *map_name,
			  __u32 key_size,
			  __u32 value_size,
			  __u32 max_entries,
			  __unused void *opts)
{
	struct bpf_create_map_attr map_attr;

	memset(&map_attr, 0, sizeof(map_attr));
	map_attr.map_type = map_type;
	map_attr.key_size = key_size;
	map_attr.value_size = value_size;
	map_attr.max_entries = max_entries;

	return bpf_create_map_xattr(&map_attr);
}

static int xsk_check_create_prog(struct bpf_insn *insns, size_t insns_cnt)
{
	struct bpf_load_program_attr prog_attr;

	memset(&prog_attr, 0, sizeof(prog_attr));
	prog_attr.prog_type = BPF_PROG_TYPE_XDP;
	prog_attr.insns = insns;
	prog_attr.insns_cnt = insns_cnt;
	prog_attr.license = "GPL";

	return bpf_load_program_xattr(&prog_attr, NULL, 0);
}
#endif

static bool xsk_check_redirect_flags(void)
{
	char data_in = 0, data_out;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = &data_in,
			    .data_out = &data_out,
			    .data_size_in = 1);
	struct bpf_insn insns[] = {
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		BPF_MOV64_IMM(BPF_REG_2, 0),
		BPF_MOV64_IMM(BPF_REG_3, XDP_PASS),
		BPF_EMIT_CALL(BPF_FUNC_redirect_map),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd, ret;
	bool detected = false;

	map_fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP, "xskmap",
				sizeof(int), sizeof(int), 1, NULL);
	if (map_fd < 0)
		return detected;

	insns[0].imm = map_fd;

	prog_fd = xsk_check_create_prog(insns, ARRAY_SIZE(insns));
	if (prog_fd < 0) {
		close(map_fd);
		return detected;
	}

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ret && opts.retval == XDP_PASS)
		detected = true;
	close(prog_fd);
	close(map_fd);
	return detected;
}

static struct xdp_program *xsk_lookup_program(int ifindex)
{
	const char *version_name = "xsk_prog_version";
	const char *prog_name = "xsk_def_prog";
	struct xdp_multiprog *multi_prog;
	struct xdp_program *prog = NULL;
	__u32 version;
	int err;

	multi_prog = xdp_multiprog__get_from_ifindex(ifindex);
	if (IS_ERR(multi_prog))
		return NULL;

	if (xdp_multiprog__is_legacy(multi_prog)) {
		prog = xdp_multiprog__main_prog(multi_prog);
		prog = strcmp(xdp_program__name(prog), prog_name) ? NULL : prog;
		goto check;
	}

	while ((prog = xdp_multiprog__next_prog(prog, multi_prog)))
		if (!strcmp(xdp_program__name(prog), prog_name))
			break;

check:
	if (!prog)
		goto out;

	err = check_xdp_prog_version(xdp_program__btf(prog), version_name, &version);
	if (err) {
		prog = ERR_PTR(err);
		goto out;
	}
	if (version > XSK_PROG_VERSION) {
		pr_warn("XSK default program version %d higher than supported %d\n", version,
			XSK_PROG_VERSION);
		prog = ERR_PTR(-EOPNOTSUPP);
	}

out:
	if (!IS_ERR_OR_NULL(prog))
		prog = xdp_program__clone(prog, 0);

	xdp_multiprog__close(multi_prog);
	return prog;
}

static int xsk_update_prog_refcnt(int refcnt_map_fd, int delta)
{
	struct bpf_map_info map_info = {};
	__u32 info_len = sizeof(map_info);
	int *value_data = NULL;
	int lock_fd, ret;
	__u32 key = 0;

	ret = bpf_obj_get_info_by_fd(refcnt_map_fd, &map_info, &info_len);
	if (ret)
		return ret;

	value_data = calloc(1, map_info.value_size);
	if (!value_data)
		return -ENOMEM;

	lock_fd = xdp_lock_acquire();
	if (lock_fd < 0) {
		ret = lock_fd;
		goto out;
	}

	/* Note, if other global variables are added before the refcnt,
	 * this changes map's value type, not number of elements,
	 * so additional offset must be applied to value_data,
	 * when reading refcount, but map key always stays zero
	 */
	ret = bpf_map_lookup_elem(refcnt_map_fd, &key, value_data);
	if (ret)
		goto unlock;

	/* If refcount is 0, program is awaiting detach and can't be used */
	if (*value_data) {
		*value_data += delta;
		ret = bpf_map_update_elem(refcnt_map_fd, &key, value_data, 0);
		if (ret)
			goto unlock;
	}

	ret = *value_data;
unlock:
	xdp_lock_release(lock_fd);
out:
	free(value_data);
	return ret;
}

static int xsk_incr_prog_refcnt(int refcnt_map_fd)
{
	return xsk_update_prog_refcnt(refcnt_map_fd, 1);
}

static int xsk_decr_prog_refcnt(int refcnt_map_fd)
{
	return xsk_update_prog_refcnt(refcnt_map_fd, -1);
}

static int __xsk_setup_xdp_prog(struct xsk_socket *xsk, int *xsks_map_fd)
{
	const char *fallback_prog = "xsk_def_xdp_prog_5.3.o";
	const char *default_prog = "xsk_def_xdp_prog.o";
	struct xsk_ctx *ctx = xsk->ctx;
	const char *file_name = NULL;
	bool attached = false;
	int err;

	ctx->xdp_prog = xsk_lookup_program(ctx->ifindex);
	if (IS_ERR(ctx->xdp_prog))
		return PTR_ERR(ctx->xdp_prog);

	ctx->refcnt_map_fd = -ENOENT;

	if (ctx->xdp_prog) {
		int refcnt;

		ctx->refcnt_map_fd = xsk_lookup_refcnt_map(xdp_program__fd(ctx->xdp_prog), NULL);
		if (ctx->refcnt_map_fd == -ENOENT)
			goto map_lookup;

		if (ctx->refcnt_map_fd < 0) {
			err = ctx->refcnt_map_fd;
			goto err_prog_load;
		}

		refcnt = xsk_incr_prog_refcnt(ctx->refcnt_map_fd);
		if (refcnt < 0) {
			err = refcnt;
			pr_debug("Error occurred when incrementing xsk XDP prog refcount: %s\n",
				 strerror(-err));
			goto err_prog_load;
		}

		if (!refcnt) {
			pr_warn("Current program is being detached, falling back on creating a new program\n");
			close(ctx->refcnt_map_fd);
			ctx->refcnt_map_fd = -ENOENT;
			xdp_program__close(ctx->xdp_prog);
			ctx->xdp_prog = NULL;
		}
	}

	if (!ctx->xdp_prog) {
		file_name = xsk_check_redirect_flags() ? default_prog : fallback_prog;
		ctx->xdp_prog = xdp_program__find_file(file_name, NULL, NULL);
		if (IS_ERR(ctx->xdp_prog))
			return PTR_ERR(ctx->xdp_prog);

		err = xsk_size_map(ctx->xdp_prog, ctx->ifname);
		if (err)
			goto err_prog_load;

		err = xdp_program__attach(ctx->xdp_prog, ctx->ifindex,
					  xsk_convert_xdp_flags(xsk->config.xdp_flags), 0);
		if (err)
			goto err_prog_load;

		attached = true;
	}

	if (ctx->refcnt_map_fd < 0) {
		ctx->refcnt_map_fd = xsk_lookup_refcnt_map(xdp_program__fd(ctx->xdp_prog),
							   file_name);
		if (ctx->refcnt_map_fd < 0 && ctx->refcnt_map_fd != -ENOENT) {
			err = ctx->refcnt_map_fd;
			goto err_prog_load;
		}
	}
map_lookup:
	ctx->xsks_map_fd = xsk_lookup_bpf_map(xdp_program__fd(ctx->xdp_prog));
	if (ctx->xsks_map_fd < 0) {
		err = ctx->xsks_map_fd;
		goto err_lookup;
	}

	if (xsk->rx) {
		err = bpf_map_update_elem(ctx->xsks_map_fd, &ctx->queue_id, &xsk->fd, 0);
		if (err)
			goto err_lookup;
	}
	if (xsks_map_fd)
		*xsks_map_fd = ctx->xsks_map_fd;

	return 0;

err_lookup:
	if (attached)
		xdp_program__detach(ctx->xdp_prog, ctx->ifindex,
				    xsk_convert_xdp_flags(xsk->config.xdp_flags), 0);
err_prog_load:
	if (ctx->refcnt_map_fd >= 0)
		close(ctx->refcnt_map_fd);
	ctx->refcnt_map_fd = -ENOENT;
	xdp_program__close(ctx->xdp_prog);
	ctx->xdp_prog = NULL;
	return err;
}

static struct xsk_ctx *xsk_get_ctx(struct xsk_umem *umem, __u64 netns_cookie, int ifindex, __u32 queue_id)
{
	struct xsk_ctx *ctx;

	if (list_empty(&umem->ctx_list))
		return NULL;

	list_for_each_entry(ctx, &umem->ctx_list, list) {
		if (ctx->netns_cookie == netns_cookie && ctx->ifindex == ifindex && ctx->queue_id == queue_id) {
			ctx->refcount++;
			return ctx;
		}
	}

	return NULL;
}

static void xsk_put_ctx(struct xsk_ctx *ctx, bool unmap)
{
	struct xsk_umem *umem = ctx->umem;
	struct xdp_mmap_offsets off;
	int err;

	if (--ctx->refcount)
		return;

	if (!unmap)
		goto out_free;

	err = xsk_get_mmap_offsets(umem->fd, &off);
	if (err)
		goto out_free;

	munmap(ctx->fill->ring - off.fr.desc, off.fr.desc + umem->config.fill_size *
	       sizeof(__u64));
	munmap(ctx->comp->ring - off.cr.desc, off.cr.desc + umem->config.comp_size *
	       sizeof(__u64));

out_free:
	list_del(&ctx->list);
	free(ctx);
}

static struct xsk_ctx *xsk_create_ctx(struct xsk_socket *xsk,
				      struct xsk_umem *umem, __u64 netns_cookie, int ifindex,
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

	ctx->netns_cookie = netns_cookie;
	ctx->ifindex = ifindex;
	ctx->refcount = 1;
	ctx->umem = umem;
	ctx->queue_id = queue_id;
	memcpy(ctx->ifname, ifname, IFNAMSIZ - 1);
	ctx->ifname[IFNAMSIZ - 1] = '\0';

	ctx->fill = fill;
	ctx->comp = comp;
	list_add(&ctx->list, &umem->ctx_list);
	return ctx;
}

static void xsk_destroy_xsk_struct(struct xsk_socket *xsk)
{
	xdp_program__close(xsk->ctx->xdp_prog);
	free(xsk->ctx);
	free(xsk);
}

int xsk_socket__update_xskmap(struct xsk_socket *xsk, int fd)
{
	struct xsk_ctx *ctx = xsk->ctx;

	ctx->xsks_map_fd = fd;
	return bpf_map_update_elem(ctx->xsks_map_fd, &ctx->queue_id, &xsk->fd, 0);
}

int xsk_setup_xdp_prog(int ifindex, int *xsks_map_fd)
{
	struct xsk_socket *xsk;
	int res;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return -ENOMEM;

	res = xsk_init_xsk_struct(xsk, ifindex);
	if (res) {
		free(xsk);
		return -EINVAL;
	}

	res = __xsk_setup_xdp_prog(xsk, xsks_map_fd);

	xsk_destroy_xsk_struct(xsk);

	return res;
}

struct xsk_socket *xsk_socket__create_opts(const char *ifname,
					   __u32 queue_id,
					   struct xsk_umem *umem,
					   struct xsk_socket_opts *opts)
{
	bool rx_setup_done = false, tx_setup_done = false;
	void *rx_map = NULL, *tx_map = NULL;
	struct sockaddr_xdp sxdp = {};
	struct xdp_mmap_offsets off;
	struct xsk_ring_prod *fill;
	struct xsk_ring_cons *comp;
	struct xsk_ring_cons *rx;
	struct xsk_ring_prod *tx;
	struct xsk_socket *xsk;
	struct xsk_ctx *ctx;
	int err, ifindex;
	__u64 netns_cookie;
	socklen_t optlen;
	bool unmap;

	if (!OPTS_VALID(opts, xsk_socket_opts)) {
		err = -EINVAL;
		goto err;
	}
	rx = OPTS_GET(opts, rx, NULL);
	tx = OPTS_GET(opts, tx, NULL);
	fill = OPTS_GET(opts, fill, NULL);
	comp = OPTS_GET(opts, comp, NULL);

	if (!umem || !(rx || tx) || (fill == NULL) ^ (comp == NULL)) {
		err = -EFAULT;
		goto err;
	}
	if (!fill && !comp) {
		fill = umem->fill_save;
		comp = umem->comp_save;
	}

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		err = -ENOMEM;
		goto err;
	}

	err = xsk_set_xdp_socket_config(&xsk->config, opts);
	if (err)
		goto out_xsk_alloc;

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
		rx_setup_done = umem->rx_ring_setup_done;
		tx_setup_done = umem->tx_ring_setup_done;
	}

	optlen = sizeof(netns_cookie);
	err = getsockopt(xsk->fd, SOL_SOCKET, SO_NETNS_COOKIE, &netns_cookie, &optlen);
	if (err) {
		if (errno != ENOPROTOOPT) {
			err = -errno;
			goto out_socket;
		}
		netns_cookie = INIT_NS;
	}

	ctx = xsk_get_ctx(umem, netns_cookie, ifindex, queue_id);
	if (!ctx) {
		if (!fill || !comp) {
			err = -EFAULT;
			goto out_socket;
		}

		ctx = xsk_create_ctx(xsk, umem, netns_cookie, ifindex, ifname, queue_id,
				     fill, comp);
		if (!ctx) {
			err = -ENOMEM;
			goto out_socket;
		}
	}
	xsk->ctx = ctx;

	if (rx && !rx_setup_done) {
		err = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING,
				 &xsk->config.rx_size,
				 sizeof(xsk->config.rx_size));
		if (err) {
			err = -errno;
			goto out_put_ctx;
		}
		if (xsk->fd == umem->fd)
			umem->rx_ring_setup_done = true;

	}
	if (tx && !tx_setup_done) {
		err = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING,
				 &xsk->config.tx_size,
				 sizeof(xsk->config.tx_size));
		if (err) {
			err = -errno;
			goto out_put_ctx;
		}
		if (xsk->fd == umem->fd)
			umem->tx_ring_setup_done = true;
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

	if (!(xsk->config.libxdp_flags & XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD)) {
		err = __xsk_setup_xdp_prog(xsk, NULL);
		if (err)
			goto out_mmap_tx;
	}

	umem->fill_save = NULL;
	umem->comp_save = NULL;
	return xsk;

out_mmap_tx:
	if (tx)
		munmap(tx_map, off.tx.desc +
		       xsk->config.tx_size * sizeof(struct xdp_desc));
out_mmap_rx:
	if (rx)
		munmap(rx_map, off.rx.desc +
		       xsk->config.rx_size * sizeof(struct xdp_desc));
out_put_ctx:
	unmap = umem->fill_save != fill;
	xsk_put_ctx(ctx, unmap);
out_socket:
	if (--umem->refcount)
		close(xsk->fd);
out_xsk_alloc:
	free(xsk);
err:
	return libxdp_err_ptr(err, true);
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
	struct xsk_socket *xsk;

	if (!xsk_ptr)
		return -EFAULT;

	DECLARE_LIBXDP_OPTS(xsk_socket_opts, opts,
		.rx = rx,
		.tx = tx,
		.fill = fill,
		.comp = comp,
	);
	if (usr_config) {
		opts.rx_size = usr_config->rx_size;
		opts.tx_size= usr_config->tx_size;
		opts.libxdp_flags = usr_config->libxdp_flags;
		opts.xdp_flags = usr_config->xdp_flags;
		opts.bind_flags = usr_config->bind_flags;
	}
	xsk = xsk_socket__create_opts(ifname, queue_id, umem, &opts);
	if (!xsk)
		return -errno;

	*xsk_ptr = xsk;
	return 0;
}

int xsk_socket__create(struct xsk_socket **xsk_ptr, const char *ifname,
		       __u32 queue_id, struct xsk_umem *umem,
		       struct xsk_ring_cons *rx, struct xsk_ring_prod *tx,
		       const struct xsk_socket_config *usr_config)
{
	if (!umem)
		return -EFAULT;

	return xsk_socket__create_shared(xsk_ptr, ifname, queue_id, umem,
					 rx, tx, umem->fill_save,
					 umem->comp_save, usr_config);
}

int xsk_umem__delete(struct xsk_umem *umem)
{
	struct xdp_mmap_offsets off;
	int err;

	if (!umem)
		return 0;

	if (umem->refcount)
		return -EBUSY;

	err = xsk_get_mmap_offsets(umem->fd, &off);
	if (!err && umem->fill_save && umem->comp_save) {
		munmap(umem->fill_save->ring - off.fr.desc,
		       off.fr.desc + umem->config.fill_size * sizeof(__u64));
		munmap(umem->comp_save->ring - off.cr.desc,
		       off.cr.desc + umem->config.comp_size * sizeof(__u64));
	}

	close(umem->fd);
	free(umem);

	return 0;
}

static void xsk_release_xdp_prog(struct xsk_socket *xsk)
{
	struct xsk_ctx *ctx = xsk->ctx;
	int value;

	if (xsk->ctx->refcnt_map_fd < 0)
		goto out;

	value = xsk_decr_prog_refcnt(ctx->refcnt_map_fd);
	if (value < 0)
		pr_warn("Error occurred when decrementing xsk XDP prog refcount: %s, please detach program yourself\n",
			strerror(-value));
	if (value)
		goto out;

	xdp_program__detach(ctx->xdp_prog, ctx->ifindex,
			    xsk_convert_xdp_flags(xsk->config.xdp_flags), 0);
out:
	xdp_program__close(ctx->xdp_prog);
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
	if (ctx->xdp_prog) {
		xsk_delete_map_entry(ctx->xsks_map_fd, ctx->queue_id);
		xsk_release_xdp_prog(xsk);
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

	xsk_put_ctx(ctx, true);

	umem->refcount--;
	/* Do not close an fd that also has an associated umem connected
	 * to it.
	 */
	if (xsk->fd != umem->fd)
		close(xsk->fd);
	free(xsk);
}
