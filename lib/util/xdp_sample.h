// SPDX-License-Identifier: GPL-2.0-only
#ifndef XDP_SAMPLE_USER_H
#define XDP_SAMPLE_USER_H

#include <bpf/libbpf.h>
#include <getopt.h>

#include <xdp/xdp_sample_shared.h>
#include "compat.h"

enum stats_mask {
	_SAMPLE_REDIRECT_MAP         = 1U << 0,
	SAMPLE_RX_CNT                = 1U << 1,
	SAMPLE_REDIRECT_ERR_CNT      = 1U << 2,
	SAMPLE_CPUMAP_ENQUEUE_CNT    = 1U << 3,
	SAMPLE_CPUMAP_KTHREAD_CNT    = 1U << 4,
	SAMPLE_EXCEPTION_CNT         = 1U << 5,
	SAMPLE_DEVMAP_XMIT_CNT       = 1U << 6,
	SAMPLE_REDIRECT_CNT          = 1U << 7,
	SAMPLE_REDIRECT_MAP_CNT      = SAMPLE_REDIRECT_CNT | _SAMPLE_REDIRECT_MAP,
	SAMPLE_REDIRECT_ERR_MAP_CNT  = SAMPLE_REDIRECT_ERR_CNT | _SAMPLE_REDIRECT_MAP,
	SAMPLE_DEVMAP_XMIT_CNT_MULTI = 1U << 8,
	SAMPLE_SKIP_HEADING          = 1U << 9,
	SAMPLE_RXQ_STATS             = 1U << 10,
	SAMPLE_DROP_OK               = 1U << 11,
};

enum sample_compat {
	SAMPLE_COMPAT_CPUMAP_KTHREAD,
	__SAMPLE_COMPAT_MAX
};
#define SAMPLE_COMPAT_MAX __SAMPLE_COMPAT_MAX

/* Exit return codes */
#define EXIT_OK			0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_BPF		4
#define EXIT_FAIL_MEM		5

int sample_setup_maps(struct bpf_map **maps, const char *ifname);
int __sample_init(int mask, int ifindex_from, int ifindex_to);
void sample_teardown(void);
int sample_run(int interval, void (*post_cb)(void *), void *ctx);
bool sample_is_compat(enum sample_compat compat_value);
bool sample_probe_cpumap_compat(void);
bool sample_probe_xdp_load_bytes(void);
void sample_check_cpumap_compat(struct bpf_program *prog,
				struct bpf_program *prog_compat);

void sample_switch_mode(void);

const char *get_driver_name(int ifindex);
int get_mac_addr(int ifindex, void *mac_addr);

#pragma GCC diagnostic push
#if !defined(__clang__) && (__GNUC__ > 7)
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
__attribute__((unused))
static inline char *safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size)
		return dst;
	strncpy(dst, src, size - 1);
	dst[size - 1] = '\0';
	return dst;
}
#pragma GCC diagnostic pop

#define __attach_tp(name)                                                      \
	({                                                                     \
		if (bpf_program__type(skel->progs.name) != BPF_PROG_TYPE_TRACING)\
			return -EINVAL;                                        \
		skel->links.name = bpf_program__attach(skel->progs.name);      \
		if (!skel->links.name)                                         \
			return -errno;                                         \
	})

#define __attach_tp_compat(name, name_compat, _compat)                         \
	({                                                                     \
	if (sample_is_compat(SAMPLE_COMPAT_ ## _compat))                       \
		  __attach_tp(name);                                           \
	else                                                                   \
		__attach_tp(name_compat);                                      \
	})

#define sample_init_pre_load(skel, ifname)                                     \
	({                                                                     \
		skel->rodata->nr_cpus = libbpf_num_possible_cpus();            \
		sample_check_cpumap_compat(skel->progs.tp_xdp_cpumap_kthread,  \
					   skel->progs.tp_xdp_cpumap_compat);  \
		sample_setup_maps((struct bpf_map *[]){                        \
			skel->maps.rx_cnt, skel->maps.rxq_cnt,                 \
			skel->maps.redir_err_cnt,                              \
			skel->maps.cpumap_enqueue_cnt,                         \
			skel->maps.cpumap_kthread_cnt,                         \
			skel->maps.exception_cnt, skel->maps.devmap_xmit_cnt,  \
			skel->maps.devmap_xmit_cnt_multi}, ifname);            \
	})

#define DEFINE_SAMPLE_INIT(name)                                   \
	static int sample_init(struct name *skel, int sample_mask, \
			       int ifindex_from, int ifindex_to)   \
	{                                                          \
		int ret;                                           \
		ret = __sample_init(sample_mask, ifindex_from,     \
				    ifindex_to);                   \
		if (ret < 0)                                       \
			return ret;                                \
		if (sample_mask & SAMPLE_REDIRECT_MAP_CNT)         \
			__attach_tp(tp_xdp_redirect_map);          \
		if (sample_mask & SAMPLE_REDIRECT_CNT)             \
			__attach_tp(tp_xdp_redirect);              \
		if (sample_mask & SAMPLE_REDIRECT_ERR_MAP_CNT)     \
			__attach_tp(tp_xdp_redirect_map_err);      \
		if (sample_mask & SAMPLE_REDIRECT_ERR_CNT)         \
			__attach_tp(tp_xdp_redirect_err);          \
		if (sample_mask & SAMPLE_CPUMAP_ENQUEUE_CNT)       \
			__attach_tp(tp_xdp_cpumap_enqueue);        \
		if (sample_mask & SAMPLE_CPUMAP_KTHREAD_CNT)       \
			__attach_tp_compat(tp_xdp_cpumap_kthread,  \
					   tp_xdp_cpumap_compat,   \
					   CPUMAP_KTHREAD);        \
		if (sample_mask & SAMPLE_EXCEPTION_CNT)            \
			__attach_tp(tp_xdp_exception);             \
		if (sample_mask & SAMPLE_DEVMAP_XMIT_CNT)          \
			__attach_tp(tp_xdp_devmap_xmit);           \
		if (sample_mask & SAMPLE_DEVMAP_XMIT_CNT_MULTI)    \
			__attach_tp(tp_xdp_devmap_xmit_multi);     \
		return 0;                                          \
	}

#endif
