/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2019 Facebook */

#ifndef __LIBXDP_LIBXDP_UTIL_H
#define __LIBXDP_LIBXDP_UTIL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Use these barrier functions instead of smp_[rw]mb() when they are
 * used in a libxdp header file. That way they can be built into the
 * application that uses libxdp.
 */
#if defined(__i386__) || defined(__x86_64__)
# define libxdp_smp_rmb() asm volatile("" : : : "memory")
# define libxdp_smp_wmb() asm volatile("" : : : "memory")
# define libxdp_smp_mb() \
	asm volatile("lock; addl $0,-4(%%rsp)" : : : "memory", "cc")
/* Hinders stores to be observed before older loads. */
# define libxdp_smp_rwmb() asm volatile("" : : : "memory")
#elif defined(__aarch64__)
# define libxdp_smp_rmb() asm volatile("dmb ishld" : : : "memory")
# define libxdp_smp_wmb() asm volatile("dmb ishst" : : : "memory")
# define libxdp_smp_mb() asm volatile("dmb ish" : : : "memory")
# define libxdp_smp_rwmb() libxdp_smp_mb()
#elif defined(__arm__)
/* These are only valid for armv7 and above */
# define libxdp_smp_rmb() asm volatile("dmb ish" : : : "memory")
# define libxdp_smp_wmb() asm volatile("dmb ishst" : : : "memory")
# define libxdp_smp_mb() asm volatile("dmb ish" : : : "memory")
# define libxdp_smp_rwmb() libxdp_smp_mb()
#else
/* Architecture missing native barrier functions. */
# define libxdp_smp_rmb() __sync_synchronize()
# define libxdp_smp_wmb() __sync_synchronize()
# define libxdp_smp_mb() __sync_synchronize()
# define libxdp_smp_rwmb() __sync_synchronize()
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBXDP_LIBXDP_UTIL_H */
