/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Arch-neutral bitsperlong for the BPF targets (bpfel/bpfeb), shadowing
 * the arch-specific asm/bitsperlong.h copies which select their value
 * with compiler backend macros a -target bpf compile never defines
 * (_MIPS_SZLONG, __x86_64__, ...).
 */
#ifndef __ASM_BITSPERLONG_H
#define __ASM_BITSPERLONG_H

#include <asm-generic/bitsperlong.h>

#endif /* __ASM_BITSPERLONG_H */
