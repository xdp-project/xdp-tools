/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Arch-neutral byteorder for the BPF targets (bpfel/bpfeb), shadowing
 * the arch-specific asm/byteorder.h copies which select their flavour
 * with compiler backend macros a -target bpf compile never defines.
 */
#ifndef _ASM_BYTEORDER_H
#define _ASM_BYTEORDER_H

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#else
#include <linux/byteorder/big_endian.h>
#endif

#endif /* _ASM_BYTEORDER_H */
