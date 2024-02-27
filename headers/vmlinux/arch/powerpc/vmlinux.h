#ifndef __VMLINUX_ARCH_POWERPC_H__
#define __VMLINUX_ARCH_POWERPC_H__

#ifdef __BPF_TRACING_H__
/* Expected include <bpf/bpf_tracing.h> */
#ifndef bpf_target_defined
#warning "Tracing need __TARGET_ARCH_powerpc defined"
#endif
#endif /*  __BPF_TRACING_H__ */

struct user_pt_regs {
	long unsigned int gpr[32];
	long unsigned int nip;
	long unsigned int msr;
	long unsigned int orig_gpr3;
	long unsigned int ctr;
	long unsigned int link;
	long unsigned int xer;
	long unsigned int ccr;
	long unsigned int softe;
	long unsigned int trap;
	long unsigned int dar;
	long unsigned int dsisr;
	long unsigned int result;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			long unsigned int gpr[32];
			long unsigned int nip;
			long unsigned int msr;
			long unsigned int orig_gpr3;
			long unsigned int ctr;
			long unsigned int link;
			long unsigned int xer;
			long unsigned int ccr;
			long unsigned int softe;
			long unsigned int trap;
			long unsigned int dar;
			long unsigned int dsisr;
			long unsigned int result;
		};
	};
	union {
		struct {
			long unsigned int ppr;
			long unsigned int kuap;
		};
		long unsigned int __pad[2];
	};
};

#endif /* __VMLINUX_ARCH_POWERPC_H__ */
