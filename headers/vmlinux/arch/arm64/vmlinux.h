#ifndef __VMLINUX_ARCH_ARM64_H__
#define __VMLINUX_ARCH_ARM64_H__

#ifdef __BPF_TRACING_H__
/* Expected include <bpf/bpf_tracing.h> */
#ifndef bpf_target_defined
#warning "Tracing need __TARGET_ARCH_arm64 defined"
#endif
#endif /*  __BPF_TRACING_H__ */

struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
	s32 syscallno;
	u32 unused2;
	u64 orig_addr_limit;
	u64 pmr_save;
	u64 stackframe[2];
	u64 lockdep_hardirqs;
	u64 exit_rcu;
};

#endif /* __VMLINUX_ARCH_ARM64_H__ */
