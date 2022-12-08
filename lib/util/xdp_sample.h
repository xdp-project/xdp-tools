// SPDX-License-Identifier: GPL-2.0-only
#ifndef XDP_SAMPLE_USER_H
#define XDP_SAMPLE_USER_H

#include <bpf/libbpf.h>
#include <getopt.h>

#include <xdp/xdp_sample_shared.h>

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
	SAMPLE_SKIP_HEADING	     = 1U << 9,
};

/* Exit return codes */
#define EXIT_OK			0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_BPF		4
#define EXIT_FAIL_MEM		5

int sample_setup_maps(struct bpf_map **maps);
int __sample_init(int mask, int ifindex_from, int ifindex_to);
void sample_teardown(void);
int sample_run(int interval, void (*post_cb)(void *), void *ctx);

void sample_switch_mode(void);

const char *get_driver_name(int ifindex);
int get_mac_addr(int ifindex, void *mac_addr);

#pragma GCC diagnostic push
#ifndef __clang__
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

#define sample_init_pre_load(skel)                                             \
	({                                                                     \
		skel->rodata->nr_cpus = libbpf_num_possible_cpus();            \
		sample_setup_maps((struct bpf_map *[]){                        \
			skel->maps.rx_cnt, skel->maps.redir_err_cnt,           \
			skel->maps.cpumap_enqueue_cnt,                         \
			skel->maps.cpumap_kthread_cnt,                         \
			skel->maps.exception_cnt, skel->maps.devmap_xmit_cnt,  \
			skel->maps.devmap_xmit_cnt_multi });                   \
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
			__attach_tp(tp_xdp_cpumap_kthread);        \
		if (sample_mask & SAMPLE_EXCEPTION_CNT)            \
			__attach_tp(tp_xdp_exception);             \
		if (sample_mask & SAMPLE_DEVMAP_XMIT_CNT)          \
			__attach_tp(tp_xdp_devmap_xmit);           \
		if (sample_mask & SAMPLE_DEVMAP_XMIT_CNT_MULTI)    \
			__attach_tp(tp_xdp_devmap_xmit_multi);     \
		return 0;                                          \
	}

#endif
