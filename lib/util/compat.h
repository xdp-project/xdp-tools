#ifndef __COMPAT_H
#define __COMPAT_H

#ifndef HAVE_LIBBPF_BTF__TYPE_CNT
static __u32 btf__type_cnt(const struct btf *btf)
{
	/* old function didn't include 'void' type in count */
	return btf__get_nr_types(btf) + 1;
}
#endif

#endif
