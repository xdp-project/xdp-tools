#ifndef __VMLINUX_ARCH_H__
#define __VMLINUX_ARCH_H__
/*
 * Notice: Defining __VMLINUX_H__ (or __KERNEL__) cause <bpf/bpf_tracing.h>
 *         header file to define architecture specific PT_REGS_PARM's.
 *         Thus, use this together with vmlinux_local.h.
 *
 * When using '-target bpf' the fallback mechanism doesn't detect right arch
 * via  compiler defines.
 *
 * Makefile system in lib/common.mk detect ARCH and defines the
 * defines __TARGET_ARCH_$(ARCH) matched on below.
 */
#if defined(__TARGET_ARCH_x86)
	#include "vmlinux/arch/x86/vmlinux.h"
#elif defined(__TARGET_ARCH_arm64)
	#include "vmlinux/arch/arm64/vmlinux.h"
#elif defined(__TARGET_ARCH_powerpc)
	#include "vmlinux/arch/powerpc/vmlinux.h"
#else
	#warning "Makefile for BPF-tracing on this arch: not supported yet"
#endif

#endif /* __VMLINUX_ARCH_H__ */
