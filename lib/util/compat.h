#ifndef __COMPAT_H
#define __COMPAT_H

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#ifndef HAVE_LIBBPF_BTF__TYPE_CNT
static inline __u32 btf__type_cnt(const struct btf *btf)
{
	/* old function didn't include 'void' type in count */
	return btf__get_nr_types(btf) + 1;
}
#endif

#ifndef HAVE_LIBBPF_BPF_PROGRAM__TYPE
static inline enum bpf_prog_type bpf_program__type(const struct bpf_program *prog)
{
	return bpf_program__get_type((struct bpf_program *)prog);
}
#endif

#ifndef HAVE_LIBBPF_BPF_OBJECT__NEXT_PROGRAM
static inline struct bpf_program *bpf_object__next_program(const struct bpf_object *obj,
							   struct bpf_program *prog)
{
	return bpf_program__next(prog, obj);
}
#endif

#ifndef HAVE_LIBBPF_BPF_PROGRAM__EXPECTED_ATTACH_TYPE
static inline enum bpf_attach_type bpf_program__expected_attach_type(const struct bpf_program *prog)
{
	return bpf_program__get_expected_attach_type((struct bpf_program *)prog);
}
#endif

#endif
