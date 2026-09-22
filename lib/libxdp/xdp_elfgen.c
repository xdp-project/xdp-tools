// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * Synthesise a minimal BPF ELF object from a raw instruction stream.
 *
 * A dispatcher component program has to be loaded as BPF_PROG_TYPE_EXT, and
 * the kernel only accepts an EXT program that carries BTF describing its own
 * function signature: check_attach_btf_id() compares the replacement's
 * prototype against the target function's via btf_check_func_type_match().
 * A caller that hands us bare instructions has no BTF and no way to add it
 * afterwards, since a program's BTF is fixed at BPF_PROG_LOAD time.
 *
 * Every XDP component has the same signature, int (struct xdp_md *), so the
 * BTF is fully determined and we can just generate it. We wrap it in a small
 * ELF object rather than loading the instructions directly, so that the
 * result is an ordinary struct bpf_object and the rest of libxdp (attach
 * target selection, EXT conversion, chain linking) needs no special case.
 *
 * Copyright (C) 2026 Simon Morley <simon.morley@mac.com>
 */

#define _GNU_SOURCE

#include <errno.h>
#include <elf.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include "libxdp_internal.h"

#ifndef EM_BPF
#define EM_BPF 247
#endif

/* The program is emitted into a section named "xdp" so that libbpf assigns it
 * BPF_PROG_TYPE_XDP on open, matching a normal clang-built component.
 */
#define SYNTH_SEC_NAME "xdp"
#define SYNTH_MAX_NAME 64

/* BTF type ids we emit, in order. */
enum {
	SYNTH_BTF_INT = 1,
	SYNTH_BTF_STRUCT,
	SYNTH_BTF_PTR,
	SYNTH_BTF_PROTO,
	SYNTH_BTF_FUNC,
};

struct synth_btf {
	struct btf_header hdr;
	struct btf_type t_int;
	__u32 int_encoding;
	struct btf_type t_struct;
	struct btf_type t_ptr;
	struct btf_type t_proto;
	struct btf_param proto_arg;
	struct btf_type t_func;
	char strings[];
} __attribute__((packed));

/* struct btf_ext_header and struct btf_ext_info_sec live in libbpf's internal
 * headers, so spell out the on-disk layout. This is the pre-core_relo 24-byte
 * header form, which libbpf still accepts.
 */
struct synth_btf_ext_hdr {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 func_info_off;
	__u32 func_info_len;
	__u32 line_info_off;
	__u32 line_info_len;
} __attribute__((packed));

struct synth_btf_ext {
	struct synth_btf_ext_hdr hdr;
	__u32 func_rec_size;
	__u32 func_sec_name_off;
	__u32 func_num_info;
	struct bpf_func_info func_rec;
	__u32 line_rec_size;
	__u32 line_sec_name_off;
	__u32 line_num_info;
	struct bpf_line_info line_rec;
} __attribute__((packed));

struct synth_buf {
	__u8 *data;
	size_t len;
	size_t cap;
};

static int buf_append(struct synth_buf *buf, const void *src, size_t len,
		      size_t *offset)
{
	if (buf->len + len > buf->cap) {
		size_t cap = buf->cap ? buf->cap : 1024;
		__u8 *new;

		while (buf->len + len > cap)
			cap *= 2;

		new = realloc(buf->data, cap);
		if (!new)
			return -ENOMEM;

		buf->data = new;
		buf->cap = cap;
	}

	if (offset)
		*offset = buf->len;

	if (src)
		memcpy(buf->data + buf->len, src, len);
	else
		memset(buf->data + buf->len, 0, len);

	buf->len += len;
	return 0;
}

static int buf_pad(struct synth_buf *buf, size_t align, size_t *offset)
{
	int err;

	while (buf->len % align) {
		err = buf_append(buf, NULL, 1, NULL);
		if (err)
			return err;
	}

	if (offset)
		*offset = buf->len;
	return 0;
}

/* Append a NUL-terminated string, returning its offset in the table. */
static size_t str_add(char *tab, size_t *used, const char *s)
{
	size_t off = *used;
	size_t len = strlen(s) + 1;

	memcpy(tab + off, s, len);
	*used += len;
	return off;
}

static struct synth_btf *build_btf(const char *prog_name, size_t *btf_size,
				   size_t *sec_name_off, size_t *file_name_off)
{
	/* "", "int", "xdp_md", "ctx", prog_name, "xdp", "<synthesised>" */
	char strings[SYNTH_MAX_NAME + 64];
	size_t used = 0, off_int, off_xdp_md, off_ctx, off_name;
	struct synth_btf *btf;
	size_t size;
	__u32 type_len;

	strings[used++] = '\0';
	off_int = str_add(strings, &used, "int");
	off_xdp_md = str_add(strings, &used, "xdp_md");
	off_ctx = str_add(strings, &used, "ctx");
	off_name = str_add(strings, &used, prog_name);
	*sec_name_off = str_add(strings, &used, SYNTH_SEC_NAME);
	*file_name_off = str_add(strings, &used, "<synthesised>");

	size = sizeof(*btf) + used;
	btf = calloc(1, size);
	if (!btf)
		return NULL;

	/* [1] int */
	btf->t_int.name_off = off_int;
	btf->t_int.info = (__u32)BTF_KIND_INT << 24;
	btf->t_int.size = sizeof(int);
	btf->int_encoding = (BTF_INT_SIGNED << 24) | 32;

	/* [2] struct xdp_md. Deliberately opaque: btf_check_func_type_match()
	 * compares the struct name, never its members, so the component does
	 * not need to agree with the kernel on the layout.
	 */
	btf->t_struct.name_off = off_xdp_md;
	btf->t_struct.info = (__u32)BTF_KIND_STRUCT << 24;
	btf->t_struct.size = sizeof(struct xdp_md);

	/* [3] struct xdp_md * */
	btf->t_ptr.info = (__u32)BTF_KIND_PTR << 24;
	btf->t_ptr.type = SYNTH_BTF_STRUCT;

	/* [4] int (struct xdp_md *) */
	btf->t_proto.info = ((__u32)BTF_KIND_FUNC_PROTO << 24) | 1;
	btf->t_proto.type = SYNTH_BTF_INT;
	btf->proto_arg.name_off = off_ctx;
	btf->proto_arg.type = SYNTH_BTF_PTR;

	/* [5] the function itself */
	btf->t_func.name_off = off_name;
	btf->t_func.info = ((__u32)BTF_KIND_FUNC << 24) | BTF_FUNC_GLOBAL;
	btf->t_func.type = SYNTH_BTF_PROTO;

	memcpy(btf->strings, strings, used);

	type_len = offsetof(struct synth_btf, strings) - sizeof(struct btf_header);
	btf->hdr.magic = BTF_MAGIC;
	btf->hdr.version = BTF_VERSION;
	btf->hdr.hdr_len = sizeof(struct btf_header);
	btf->hdr.type_off = 0;
	btf->hdr.type_len = type_len;
	btf->hdr.str_off = type_len;
	btf->hdr.str_len = used;

	*btf_size = size;
	return btf;
}

/**
 * xdp_synthesise_elf - build a BPF ELF object around a raw instruction stream
 * @insns: the instructions
 * @insn_cnt: number of instructions
 * @prog_name: name to give the program, also used as its BTF function name
 * @out_size: set to the size of the returned buffer
 *
 * Returns a malloc()ed ELF image suitable for bpf_object__open_mem(), or NULL
 * with errno set.
 */
void *xdp_synthesise_elf(const struct bpf_insn *insns, size_t insn_cnt,
			 const char *prog_name, size_t *out_size)
{
	size_t off_prog, off_license, off_btf, off_ext, off_sym, off_str,
		off_shstr, off_shdr, btf_size, sec_name_off, file_name_off;
	size_t insns_size = insn_cnt * sizeof(struct bpf_insn);
	size_t shstr_used = 0, str_used = 0;
	size_t name_prog, name_license, name_btf, name_ext, name_sym, name_str,
		name_shstr, sym_name;
	struct synth_buf buf = {};
	struct synth_btf_ext ext = {};
	struct synth_btf *btf = NULL;
	char shstrings[64], strings[SYNTH_MAX_NAME + 1];
	Elf64_Shdr shdr[8] = {};
	Elf64_Ehdr *ehdr;
	Elf64_Sym syms[2] = {};
	int err;

	if (!insns || !insn_cnt || !prog_name || !out_size) {
		errno = EINVAL;
		return NULL;
	}

	if (strlen(prog_name) >= SYNTH_MAX_NAME) {
		pr_warn("Program name '%s' too long (max %d)\n", prog_name,
			SYNTH_MAX_NAME - 1);
		errno = ENAMETOOLONG;
		return NULL;
	}

	btf = build_btf(prog_name, &btf_size, &sec_name_off, &file_name_off);
	if (!btf) {
		errno = ENOMEM;
		return NULL;
	}

	/* .BTF.ext carries the func_info record that tells the kernel which
	 * BTF function describes this program; without it the EXT type check
	 * has nothing to compare against.
	 */
	ext.hdr.magic = BTF_MAGIC;
	ext.hdr.version = BTF_VERSION;
	ext.hdr.hdr_len = sizeof(struct synth_btf_ext_hdr);
	ext.hdr.func_info_off = 0;
	ext.hdr.func_info_len = sizeof(__u32) * 3 + sizeof(struct bpf_func_info);
	ext.hdr.line_info_off = ext.hdr.func_info_len;
	ext.hdr.line_info_len = sizeof(__u32) * 3 + sizeof(struct bpf_line_info);
	ext.func_rec_size = sizeof(struct bpf_func_info);
	ext.func_sec_name_off = sec_name_off;
	ext.func_num_info = 1;
	ext.func_rec.insn_off = 0;
	ext.func_rec.type_id = SYNTH_BTF_FUNC;
	/* libbpf warns if a program has func_info but no line_info, so emit a
	 * single placeholder record pointing at an empty source location.
	 */
	ext.line_rec_size = sizeof(struct bpf_line_info);
	ext.line_sec_name_off = sec_name_off;
	ext.line_num_info = 1;
	ext.line_rec.insn_off = 0;
	ext.line_rec.file_name_off = file_name_off;
	ext.line_rec.line_off = file_name_off;
	ext.line_rec.line_col = 0;

	shstrings[shstr_used++] = '\0';
	name_prog = str_add(shstrings, &shstr_used, SYNTH_SEC_NAME);
	name_license = str_add(shstrings, &shstr_used, "license");
	name_btf = str_add(shstrings, &shstr_used, ".BTF");
	name_ext = str_add(shstrings, &shstr_used, ".BTF.ext");
	name_sym = str_add(shstrings, &shstr_used, ".symtab");
	name_str = str_add(shstrings, &shstr_used, ".strtab");
	name_shstr = str_add(shstrings, &shstr_used, ".shstrtab");

	strings[str_used++] = '\0';
	sym_name = str_add(strings, &str_used, prog_name);

	syms[1].st_name = sym_name;
	syms[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
	syms[1].st_shndx = 1;
	syms[1].st_value = 0;
	syms[1].st_size = insns_size;

	err = buf_append(&buf, NULL, sizeof(Elf64_Ehdr), NULL);
	err = err ?: buf_pad(&buf, sizeof(struct bpf_insn), &off_prog);
	err = err ?: buf_append(&buf, insns, insns_size, NULL);
	err = err ?: buf_append(&buf, "GPL", sizeof("GPL"), &off_license);
	err = err ?: buf_pad(&buf, 4, &off_btf);
	err = err ?: buf_append(&buf, btf, btf_size, NULL);
	err = err ?: buf_pad(&buf, 4, &off_ext);
	err = err ?: buf_append(&buf, &ext, sizeof(ext), NULL);
	err = err ?: buf_pad(&buf, 8, &off_sym);
	err = err ?: buf_append(&buf, syms, sizeof(syms), NULL);
	err = err ?: buf_append(&buf, strings, str_used, &off_str);
	err = err ?: buf_append(&buf, shstrings, shstr_used, &off_shstr);
	err = err ?: buf_pad(&buf, 8, &off_shdr);
	if (err)
		goto err_out;

	shdr[1] = (Elf64_Shdr){ .sh_name = name_prog,
				.sh_type = SHT_PROGBITS,
				.sh_flags = SHF_ALLOC | SHF_EXECINSTR,
				.sh_offset = off_prog,
				.sh_size = insns_size,
				.sh_addralign = sizeof(struct bpf_insn) };
	shdr[2] = (Elf64_Shdr){ .sh_name = name_license,
				.sh_type = SHT_PROGBITS,
				.sh_flags = SHF_ALLOC | SHF_WRITE,
				.sh_offset = off_license,
				.sh_size = sizeof("GPL"),
				.sh_addralign = 1 };
	shdr[3] = (Elf64_Shdr){ .sh_name = name_btf,
				.sh_type = SHT_PROGBITS,
				.sh_offset = off_btf,
				.sh_size = btf_size,
				.sh_addralign = 4 };
	shdr[4] = (Elf64_Shdr){ .sh_name = name_ext,
				.sh_type = SHT_PROGBITS,
				.sh_offset = off_ext,
				.sh_size = sizeof(ext),
				.sh_addralign = 4 };
	shdr[5] = (Elf64_Shdr){ .sh_name = name_sym,
				.sh_type = SHT_SYMTAB,
				.sh_offset = off_sym,
				.sh_size = sizeof(syms),
				.sh_link = 6,
				.sh_info = 1,
				.sh_addralign = 8,
				.sh_entsize = sizeof(Elf64_Sym) };
	shdr[6] = (Elf64_Shdr){ .sh_name = name_str,
				.sh_type = SHT_STRTAB,
				.sh_offset = off_str,
				.sh_size = str_used,
				.sh_addralign = 1 };
	shdr[7] = (Elf64_Shdr){ .sh_name = name_shstr,
				.sh_type = SHT_STRTAB,
				.sh_offset = off_shstr,
				.sh_size = shstr_used,
				.sh_addralign = 1 };

	err = buf_append(&buf, shdr, sizeof(shdr), NULL);
	if (err)
		goto err_out;

	ehdr = (Elf64_Ehdr *)buf.data;
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_type = ET_REL;
	ehdr->e_machine = EM_BPF;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_ehsize = sizeof(Elf64_Ehdr);
	ehdr->e_shentsize = sizeof(Elf64_Shdr);
	ehdr->e_shnum = ARRAY_SIZE(shdr);
	ehdr->e_shstrndx = 7;
	ehdr->e_shoff = off_shdr;

	free(btf);
	*out_size = buf.len;
	return buf.data;

err_out:
	free(btf);
	free(buf.data);
	errno = -err;
	return NULL;
}
