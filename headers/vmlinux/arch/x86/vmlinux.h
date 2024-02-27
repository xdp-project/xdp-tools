#ifndef __VMLINUX_ARCH_X86_H__
#define __VMLINUX_ARCH_X86_H__

#ifdef __BPF_TRACING_H__
/* Expected include <bpf/bpf_tracing.h> */
#ifndef bpf_target_defined
#warning "Tracing need __TARGET_ARCH_x86 defined"
#endif
#endif /*  __BPF_TRACING_H__ */

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

#endif /* __VMLINUX_ARCH_X86_H__ */
