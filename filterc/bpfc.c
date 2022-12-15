/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/filter.h>

#include <libelf.h>
#include <bpf/btf.h>

// We need the bpf_insn and bpf_program definitions from libpcap, but they
// conflict with the Linux/libbpf definitions. Rename the libpcap structs to
// prevent the conflicts.
#define bpf_insn cbpf_insn
#define bpf_program cbpf_program
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#undef bpf_insn
#undef bpf_program

#include "logging.h"
#include "util.h"

#include "filter.h"
#include "bpfc.h"

#define BPFC_DEFAULT_SNAP_LEN 262144
#define BPFC_ERRBUFF_SZ 512 + STRERR_BUFSIZE
#define BPFC_PROG_SYM_NAME "filterc_prog"

static char bpfc_errbuff[BPFC_ERRBUFF_SZ + 1];

char *bpfc_geterr()
{
	return bpfc_errbuff;
}

#define bpfc_error(format, ...)						\
	do {								\
		snprintf(bpfc_errbuff, BPFC_ERRBUFF_SZ, format,		\
			 ## __VA_ARGS__);				\
		bpfc_errbuff[BPFC_ERRBUFF_SZ] = 0;			\
	} while (0)

struct cbpf_program *cbpf_program_from_filter(char *filter)
{
	pcap_t *pcap = NULL;
	struct cbpf_program *prog = NULL;
	int err;

	pcap = pcap_open_dead(DLT_EN10MB, BPFC_DEFAULT_SNAP_LEN);
	if (!pcap) {
		goto error;
	}

	prog = malloc(sizeof(struct cbpf_program));
	if (!prog) {
		goto error;
	}

	err = pcap_compile(pcap, prog, filter, 1, PCAP_NETMASK_UNKNOWN);
	if (err) {
		goto error;
	}

	goto out;

error:
	if (prog) {
		free(prog);
		prog = NULL;
	}
out:
	if (pcap)
		pcap_close(pcap);
	return prog;
}

void cbpf_program_dump(struct cbpf_program *prog)
{
	printf("cBPF program (insn cnt = %d)\n", prog->bf_len);
	bpf_dump(prog, 1);
}

void cbpf_program_free(struct cbpf_program *prog)
{
	pcap_freecode(prog);
	free(prog);
}

struct ebpf_program {
	struct bpf_insn *insns;
	size_t insns_cnt;
};

/**
 * Converts a cBPF program to a eBPF XDP program that passes the verifier. The
 * design is similar to what bpf_convert_filter does. The conversion happens in
 * two passes:
 *   (1) convert to check the resulting length and calculate jump offsets
 *   (2) do the conversion again and store the result with the correct jump
 *       offsets.
 *
 * The resulting program uses the following registers (defined here and in
 * filter.h):
 *   r0: Register A of cBPF, return value
 *   r1: Register X of cBPF
 *   r2: Temporary register for calculations
 *   r3: Keeps xdp_md.data for guards
 *   r4: Keeps xdp_md.data_end for guards
 *
 * We can freely use any register (caller-saved and callee-saved) right now.
 * Caller-saved registers (r0-r5) can be used because we are not calling into
 * any other functions; callee-saved registers (r6-r9) can be used because the
 * JIT will take of saving them for us. If we start calling other functions, we
 * need to have X, data and data_end in callee-saved registers to persist them
 * across calls.
 */

#undef BPF_REG_X /* already defined differently in filter.h */
#define BPF_REG_X	BPF_REG_1
#define BPF_REG_DP	BPF_REG_3	/* data ptr  */
#define BPF_REG_DEP	BPF_REG_4	/* data end ptr */

static int convert_cbpf(struct cbpf_program *cbpf_prog,
			struct ebpf_program *prog)
{
	// NULL on first pass and allocated for the second pass
	struct bpf_insn *new_insn, *first_insn = NULL;
	struct cbpf_insn *fp;
	int *addrs = NULL;
	size_t insns_cnt = 0;
	u_int i;
	int code, target, imm, src_reg, dst_reg, bpf_src, stack_off, err = 0;
	int match_insn = -1, nomatch_insn = -1;

	addrs = calloc(sizeof(*addrs), cbpf_prog->bf_len);
	if (!addrs) {
		bpfc_error("Failed to allocate memory for offset calculation");
		err = errno;
		goto out;
	}

do_pass:
	new_insn = first_insn;
	fp = cbpf_prog->bf_insns;

	if (first_insn) {
		/* Load data and data_end into registers */
		*new_insn++ = BPF_LDX_MEM(BPF_W, BPF_REG_DP, BPF_REG_ARG1,
					  offsetof(struct xdp_md, data));
		*new_insn++ = BPF_LDX_MEM(BPF_W, BPF_REG_DEP, BPF_REG_ARG1,
					  offsetof(struct xdp_md, data_end));
	} else {
		new_insn += 2;
	}

	for (i = 0; i < cbpf_prog->bf_len; fp++, i++) {
		struct bpf_insn tmp_insns[32] = { };
		struct bpf_insn *insn = tmp_insns;

		addrs[i] = new_insn - first_insn;

		switch (fp->code) {
		/* All arithmetic insns and skb loads map as-is. */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_NEG:
			if (fp->code == (BPF_ALU | BPF_DIV | BPF_X) ||
			    fp->code == (BPF_ALU | BPF_MOD | BPF_X)) {
				*insn++ = BPF_MOV32_REG(BPF_REG_X, BPF_REG_X);
				/* Error with exception code on div/mod by 0.
				 * For cBPF programs, this was always return 0.
				 */
				*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_X, 0, 2);
				*insn++ = BPF_ALU32_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
				*insn++ = BPF_EXIT_INSN();
			}

			// verifier wants src to be 0 when using imm
			if (BPF_SRC(fp->code) == BPF_X)
				src_reg = BPF_REG_X;
			else
				src_reg = 0;

			*insn++ = BPF_RAW_INSN(fp->code, BPF_REG_A, src_reg, 0, fp->k);
			break;

#define BPF_JMP_INSN(insn_code, dst, src, immv, target) ({		\
		int32_t off;						\
									\
		if (target >= (int)cbpf_prog->bf_len ||			\
		    (first_insn && target < 0)) {			\
			bpfc_error("insn %d: Invalid jump target", i);	\
			err = EINVAL;					\
			goto out;					\
		}							\
		off = addrs[target] - addrs[i] - 1;			\
		/* Adjust pc relative offset for 2nd or 3rd insn. */	\
		off -= insn - tmp_insns;				\
		/* Reject anything not fitting into insn->off. */	\
		if (off < INT16_MIN || off > INT16_MAX) {		\
			bpfc_error("insn %d: Jump too big for eBPF offsets", i);\
			err = EINVAL;					\
			goto out;					\
		}							\
									\
		(struct bpf_insn) {					\
			.code  = insn_code,				\
			.dst_reg = dst,					\
			.src_reg = src,					\
			.off   = off,					\
			.imm   = immv };				\
	})
#define BPF_JA_INSN(insn_code, target)		\
	BPF_JMP_INSN(insn_code, 0, 0, 0, target)

		case BPF_JMP | BPF_JA:
			*insn++ = BPF_JA_INSN(fp->code, (int)(i + fp->k + 1));
			break;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
			code = 0;
			target = 0;
			imm = 0;
			src_reg = 0;
			dst_reg = 0;
			bpf_src = 0;

			if (BPF_SRC(fp->code) == BPF_K && (int) fp->k < 0) {
				/* BPF immediates are signed, zero extend
				 * immediate into tmp register and use it
				 * in compare insn.
				 */
				*insn++ = BPF_MOV32_IMM(BPF_REG_TMP, fp->k);

				dst_reg = BPF_REG_A;
				src_reg = BPF_REG_TMP;
				bpf_src = BPF_X;
			} else {
				dst_reg = BPF_REG_A;
				imm = fp->k;
				bpf_src = BPF_SRC(fp->code);
				src_reg = bpf_src == BPF_X ? BPF_REG_X : 0;
			}

			/* Other jumps are mapped into two insns: Jxx and JA. */
			code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
			target = i + fp->jt + 1;
			*insn++ = BPF_JMP_INSN(code, dst_reg, src_reg, imm, target);

			code = BPF_JMP | BPF_JA;
			target = i + fp->jf + 1;
			*insn++ = BPF_JA_INSN(code, target);
			break;

		/* RET_K is remaped into 2 insns. RET_A case doesn't need an
		 * extra mov as BPF_REG_0 is already mapped into BPF_REG_A.
		 */
		case BPF_RET | BPF_A:
		case BPF_RET | BPF_K:
			if (BPF_RVAL(fp->code) == BPF_K) {
				if (fp->k == 0) {
					nomatch_insn = i;
					imm = XDP_DROP;
				} else {
					match_insn = i;
					imm = XDP_PASS;
				}
				*insn++ = BPF_MOV32_IMM(BPF_REG_0, imm);
			}

			*insn++ = BPF_EXIT_INSN();
			break;

		case BPF_LD | BPF_ABS | BPF_W:
		case BPF_LD | BPF_ABS | BPF_H:
		case BPF_LD | BPF_ABS | BPF_B:
		case BPF_LD | BPF_IND | BPF_W:
		case BPF_LD | BPF_IND | BPF_H:
		case BPF_LD | BPF_IND | BPF_B:
		//case ldxb 4*([]&0xf)
		case BPF_LDX | BPF_MSH | BPF_B:
			dst_reg = 0;

			if (BPF_CLASS(fp->code) == BPF_LDX)
				dst_reg = BPF_REG_X;
			else
				dst_reg = BPF_REG_A;

			*insn++ = BPF_MOV64_REG(dst_reg, BPF_REG_DP);
			if (BPF_MODE(fp->code) == BPF_IND)
				*insn++ = BPF_ALU64_REG(BPF_ADD, dst_reg, BPF_REG_X);

			// Guard packet access
			int sz = 0;
			if (BPF_SIZE(fp->code) == BPF_B)
				sz = 1;
			else if (BPF_SIZE(fp->code) == BPF_H)
				sz = 2;
			else if (BPF_SIZE(fp->code) == BPF_W)
				sz = 4;
			*insn++ = BPF_MOV64_REG(BPF_REG_TMP, dst_reg);
			*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_TMP, fp->k + sz);
			*insn++ = BPF_JMP_INSN(BPF_JMP | BPF_X | BPF_JGT,
					       BPF_REG_TMP, BPF_REG_DEP, 0,
					       (nomatch_insn != -1 ? nomatch_insn : 0));

			*insn++ = BPF_LDX_MEM(BPF_SIZE(fp->code), dst_reg, dst_reg, fp->k);
			if (sz > 1)
				*insn++ = BPF_ENDIAN(BPF_FROM_BE, dst_reg, sz * 8);

			if (BPF_MODE(fp->code) == BPF_MSH) {
				/* dst &= 0xf */
				*insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg, 0xf);
				/* dst <<= 2 */
				*insn++ = BPF_ALU32_IMM(BPF_LSH, dst_reg, 2);
			}
			break;

		/* Store to stack. */
		case BPF_ST:
		case BPF_STX:
			stack_off = fp->k * 4  + 4;
			*insn = BPF_STX_MEM(BPF_W, BPF_REG_FP, BPF_CLASS(fp->code) ==
					    BPF_ST ? BPF_REG_A : BPF_REG_X,
					    -stack_off);
			break;

		/* Load from stack. */
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
			stack_off = fp->k * 4  + 4;
			*insn = BPF_LDX_MEM(BPF_W, BPF_CLASS(fp->code) == BPF_LD  ?
					    BPF_REG_A : BPF_REG_X, BPF_REG_FP,
					    -stack_off);
			break;

		/* A = K or X = K */
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
			*insn++ = BPF_MOV32_IMM(BPF_CLASS(fp->code) == BPF_LD ?
					      BPF_REG_A : BPF_REG_X, fp->k);
			break;

		/* X = A */
		case BPF_MISC | BPF_TAX:
			*insn++ = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
			break;

		/* A = X */
		case BPF_MISC | BPF_TXA:
			*insn++ = BPF_MOV64_REG(BPF_REG_A, BPF_REG_X);
			break;

		/* Unknown instruction. */
		default:
			bpfc_error("Unknown instruction: %d", i);
			err = EINVAL;
			goto out;
		}

		insns_cnt = insn - tmp_insns;
		if (first_insn)
			memcpy(new_insn, tmp_insns, sizeof(*insn) * insns_cnt);
		new_insn += insns_cnt;


	}

	insns_cnt = new_insn - first_insn;
	if (!first_insn) {
		// Checking prerequisites for second pass
		if (match_insn == -1 || nomatch_insn == -1) {
			bpfc_error("Failed to detect match and no match return" \
				   " instructions. Most likely, the cBPF code" \
				   " does not return both as immediate values.");
			err = -EINVAL;
			goto out;
		}

		first_insn = calloc(sizeof(*first_insn), insns_cnt);
		if (!new_insn) {
			bpfc_error("Failed to allocate memory for eBPF instructions");
			err = errno;
			goto out;
		}
		goto do_pass;
	}

out:
	if (err) {
		free(first_insn);
	} else {
		prog->insns = first_insn;
		prog->insns_cnt = insns_cnt;
	}

	free(addrs);
	return err;
}

struct ebpf_program *ebpf_program_from_cbpf(struct cbpf_program *cbpf_prog)
{
	struct ebpf_program *prog = NULL;
	int err;

	prog = calloc(sizeof(*prog), 1);
	if (!prog) {
		goto error;
	}

	err = convert_cbpf(cbpf_prog, prog);
	if (err)
		goto error;

	return prog;

error:
	if (prog)
		free(prog);
	return NULL;
}

struct table {
	void *data;
	size_t len;
};

static struct table *strtab_init()
{
	struct table *tab = calloc(sizeof(struct table), 1);
	if (!tab)
		return NULL;

	tab->data = calloc(sizeof(char), 1);
	if (!tab->data) {
		free (tab);
		return NULL;
	}

	tab->len = 1;
	return tab;
}

static struct table *symtab_init()
{
	Elf64_Sym *sym;

	struct table *tab = calloc(sizeof(struct table), 1);
	if (!tab)
		return NULL;

	sym = calloc(sizeof(*sym), 1);
	if (!sym) {
		free (tab);
		return NULL;
	}

	tab->data = sym;
	tab->len = sizeof(*sym);
	return tab;
}

static int strtab_add(struct table *strtab, char *str)
{
	size_t add_len = strlen(str) + 1;
	size_t new_len = strtab->len + add_len;
	size_t off = strtab->len;
	char *new_data = NULL;

	new_data = realloc(strtab->data, new_len);
	if (!new_data)
		return -errno;

	strncpy(new_data + off, str, add_len);
	new_data[new_len - 1] = 0;

	strtab->data = new_data;
	strtab->len = new_len;

	return off;
}

static int symtab_add(struct table *symtab, Elf64_Sym *sym)
{
	size_t add_len = sizeof(*sym);
	size_t new_len = symtab->len + add_len;
	size_t off = symtab->len;
	char *new_data = NULL;

	new_data = realloc(symtab->data, new_len);
	if (!new_data)
		return -errno;

	memcpy(new_data + off, sym, add_len);

	symtab->data = new_data;
	symtab->len = new_len;

	return 0;
}

static void table_free(struct table *tab)
{
	free(tab->data);
	free(tab);
}

static Elf_Scn *add_elf_sec(Elf *elf, struct table *strtab, char *name)
{
	Elf_Scn *scn;
	Elf64_Shdr *shdr;
	int off;

	scn = elf_newscn(elf);
	if (!scn)
		return NULL;

	shdr = elf64_getshdr(scn);
	if (!shdr)
		return NULL;

	off = strtab_add(strtab, name);
	if (off < 0)
		return NULL;

	shdr->sh_name = off;

	return scn;
}

static Elf_Scn *add_elf_strtab(Elf *elf, struct table *strtab)
{
	Elf_Scn *scn;
	Elf64_Shdr *shdr;

	scn = add_elf_sec(elf, strtab, ".strtab");
	if (!scn)
		return NULL;

	shdr = elf64_getshdr(scn);
	if (!shdr)
		return NULL;

	shdr->sh_type = SHT_STRTAB;
	shdr->sh_addralign = 1;
	//shdr->sh_flags = SHF_STRINGS;
	//shdr->sh_offset = 0;
	//shdr->sh_link = 0;
	//shdr->sh_info = 0;
	//shdr->sh_entsize = 0;

	return scn;
}

static int finalize_elf_strtab(Elf *elf, Elf_Scn *scn, struct table *strtab)
{
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *shdr;
	Elf_Data *data;

	shdr = elf64_getshdr(scn);
	if (!shdr)
		return EINVAL;

	shdr->sh_size = strtab->len;

	data = elf_newdata(scn);
	if (!data)
		return EINVAL;

	data->d_align = 1;
	data->d_off = 0LL;
	data->d_buf = strtab->data;
	data->d_type = ELF_T_BYTE;
	data->d_size = strtab->len;

	elf_hdr = elf64_getehdr(elf);
	if (!elf_hdr)
		return EINVAL;

	elf_hdr->e_shstrndx = elf_ndxscn(scn);
	return 0;
}

static Elf_Scn *add_elf_symtab(Elf *elf, struct table *strtab,
			       struct table *symtab, int strtab_ndx)
{
	Elf_Scn *scn;
	Elf64_Shdr *shdr;
	Elf_Data *data;

	scn = add_elf_sec(elf, strtab, ".symtab");
	if (!scn)
		return NULL;

	shdr = elf64_getshdr(scn);
	if (!shdr)
		return NULL;

	shdr->sh_type = SHT_SYMTAB;
	shdr->sh_addralign = 8;
	shdr->sh_size = symtab->len;
	shdr->sh_link = strtab_ndx;
	// sh_info should be the number of local symbols, but why? elfutils
	// does not even have a warnign for this, just binutils.
	//shdr->sh_info = symtab->len / sizeof(Elf64_Sym);
	shdr->sh_entsize = sizeof(Elf64_Sym);

	data = elf_newdata(scn);
	if (!data)
		return NULL;

	data->d_align = 8;
	data->d_off = 0LL;
	data->d_buf = symtab->data;
	data->d_type = ELF_T_BYTE;
	data->d_size = symtab->len;

	return scn;
}

static Elf_Scn *add_elf_bpf_prog(Elf *elf, struct table *strtab,
				 struct table *symtab,
				 struct ebpf_program *prog)
{
	Elf_Scn *scn;
	Elf64_Shdr *shdr;
	Elf_Data *data;
	Elf64_Sym sym = {0};
	int off, err;
	int prog_size = prog->insns_cnt * 8;

	scn = add_elf_sec(elf, strtab, "xdp");
	if (!scn)
		return NULL;

	off = strtab_add(strtab, BPFC_PROG_SYM_NAME);
	if (off < 0)
		return NULL;

	sym.st_name = off;
	sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
	sym.st_shndx = elf_ndxscn(scn);
	sym.st_size = prog_size;
	err = symtab_add(symtab, &sym);
	if (err)
		return NULL;

	shdr = elf64_getshdr(scn);
	if (!shdr)
		return NULL;

	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_addralign = 8;
	shdr->sh_size = prog_size;
	shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;

	data = elf_newdata(scn);
	if (!data)
		return NULL;

	data->d_align = 8;
	data->d_off = 0LL;
	data->d_buf = prog->insns;
	data->d_type = ELF_T_BYTE;
	data->d_size = prog_size;

	return scn;
}

/**
 * Populates the load opts with the necessary BTF data to allow loading of the
 * bare instructions. The structure of the BTF information is the same as from
 * a plain XDP program, i.e., similar to the following (with different order):
 *
 * [1] PTR '(anon)' type_id=2
 * [2] STRUCT 'xdp_md' size=24 vlen=6
 *         'data' type_id=3 bits_offset=0
 *         'data_end' type_id=3 bits_offset=32
 *         'data_meta' type_id=3 bits_offset=64
 *         'ingress_ifindex' type_id=3 bits_offset=96
 *         'rx_queue_index' type_id=3 bits_offset=128
 *         'egress_ifindex' type_id=3 bits_offset=160
 * [3] TYPEDEF '__u32' type_id=4
 * [4] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)
 * [5] FUNC_PROTO '(anon)' ret_type_id=6 vlen=1
 *         'ctx' type_id=1
 * [6] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
 * [7] FUNC 'prog' type_id=5 linkage=global
 */
struct btf *build_xdp_btf()
{
	char errmsg[STRERR_BUFSIZE];
	int err = 0;
	struct btf *btf;

	btf = btf__new_empty();
	if (!btf) {
		err = errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create btf structure: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int unsig_int_id = btf__add_int(btf, "unsigned int", 4, 0);
	if (unsig_int_id < 0) {
		err = unsig_int_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'unsigned int' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int u32_id = btf__add_typedef(btf, "__u32", unsig_int_id);
	if (u32_id < 0) {
		err = u32_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create '__u32' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int xdp_md_id = btf__add_struct(btf, "xdp_md", 24);
	if (xdp_md_id < 0) {
		err = xdp_md_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "data", u32_id, 0, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' field 'data' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "data_end", u32_id, 32, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' field 'data_end' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "data_meta", u32_id, 64, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' field 'data_meta' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "ingress_ifindex", u32_id, 96, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' field 'ingress_ifindex' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "rx_queue_index", u32_id, 128, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' field 'rx_queue_index' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	err = btf__add_field(btf, "egress_ifindex", u32_id, 160, 32);
	if (err < 0) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md' field 'egress_ifindex' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int ptr_xdp_md_id = btf__add_ptr(btf, xdp_md_id);
	if (ptr_xdp_md_id < 0) {
		err = ptr_xdp_md_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create 'xdp_md *' btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int func_return_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (func_return_id < 0) {
		err = func_return_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create return int btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int func_proto_id = btf__add_func_proto(btf, func_return_id);
	if (func_proto_id < 0) {
		err = func_proto_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create func proto btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int ctx_param_id = btf__add_func_param(btf, "ctx", ptr_xdp_md_id);
	if (ctx_param_id < 0) {
		err = ctx_param_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create ctx param btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	int xdp_prog_func_id = btf__add_func(btf, BPFC_PROG_SYM_NAME,
					     BTF_FUNC_GLOBAL, func_proto_id);
	if (xdp_prog_func_id < 0) {
		err = xdp_prog_func_id;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		bpfc_error("Could not create xdp func btf: %s (%d)",
			   errmsg, err);
		goto out;
	}

	return btf;

out:
	if (btf)
		btf__free(btf);

	return NULL;
}

static Elf_Scn *add_elf_btf(Elf *elf, struct table *strtab, struct btf *btf)
{
	Elf_Scn *scn;
	Elf64_Shdr *shdr;
	Elf_Data *data;
	__u32 btf_size = 0;

	scn = add_elf_sec(elf, strtab, ".BTF");
	if (!scn)
		return NULL;

	shdr = elf64_getshdr(scn);
	if (!shdr)
		return NULL;

	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_addralign = 4;

	data = elf_newdata(scn);
	if (!data)
		return NULL;

	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = (void *)btf__raw_data(btf, &btf_size);
	data->d_type = ELF_T_BYTE;

	data->d_size = btf_size;
	shdr->sh_size = btf_size;

	return scn;
}

int ebpf_program_write_elf(struct ebpf_program *prog, char *filename)
{
	int err = 0, fd = -1;
	Elf *elf = NULL;
	Elf_Scn *scn, *scn_strtab;
	Elf64_Ehdr *elf_hdr;
	struct table *strtab = NULL, *symtab = NULL;
	struct btf *btf = NULL;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		err = EINVAL;
		bpfc_error("libelf initialization failed");
		goto out;
	}

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = errno;
		bpfc_error("Failed to create '%s': %d", filename, err);
		goto out;
	}

	elf = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!elf) {
		err = EINVAL;
		bpfc_error("Failed to create ELF object");
		goto out;
	}

	/* ELF header */
	elf_hdr = elf64_newehdr(elf);
	if (!elf_hdr) {
		err = EINVAL;
		bpfc_error("Failed to create ELF header");
		goto out;
	}

	elf_hdr->e_machine = EM_BPF;
	elf_hdr->e_type = ET_REL;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	elf_hdr->e_ident[EI_DATA] = ELFDATA2LSB;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	elf_hdr->e_ident[EI_DATA] = ELFDATA2MSB;
#else
#error "Unknown __BYTE_ORDER__"
#endif

	strtab = strtab_init();
	if (!strtab) {
		err = EINVAL;
		bpfc_error("Failed to initialize strtab");
		goto out;
	}
	scn_strtab = add_elf_strtab(elf, strtab);
	if (!scn_strtab) {
		bpfc_error("Failed to add STRTAB section to ELF object");
		goto out;
	}

	symtab = symtab_init();
	if (!strtab) {
		err = EINVAL;
		bpfc_error("Failed to initialize symtab");
		goto out;
	}

	scn = add_elf_bpf_prog(elf, strtab, symtab, prog);
	if (!scn) {
		err = EINVAL;
		bpfc_error("Failed to add BPF program section to ELF object");
		goto out;
	}

	btf = build_xdp_btf();
	if (!btf) {
		err = EINVAL;
		bpfc_error("Failed to add build BTF information");
		goto out;
	}

	scn = add_elf_btf(elf, strtab, btf);
	if (!scn) {
		err = EINVAL;
		bpfc_error("Failed to add BTF section to ELF object");
		goto out;
	}

	scn = add_elf_symtab(elf, strtab, symtab, elf_ndxscn(scn_strtab));
	if (!scn) {
		bpfc_error("Failed to add SYMTAB section to ELF object");
		goto out;
	}

	err = finalize_elf_strtab(elf, scn_strtab, strtab);
	if (err) {
		bpfc_error("Failed to finalize strtab");
		goto out;
	}

	/* Finalize ELF layout */
	if (elf_update(elf, ELF_C_NULL) < 0) {
		err = EINVAL;
		bpfc_error("Failed to finalize ELF layout: %s",
			   elf_errmsg(elf_errno()));
		goto out;
	}

	/* Write out final ELF contents */
	if (elf_update(elf, ELF_C_WRITE) < 0) {
		err = EINVAL;
		bpfc_error("Failed to write ELF contents: %s",
			   elf_errmsg(elf_errno()));
		goto out;
	}

out:
	if (btf)
		btf__free(btf);
	if (strtab)
		table_free(strtab);
	if (symtab)
		table_free(symtab);
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);

	return err;
}

void ebpf_program_dump(struct ebpf_program *prog)
{
	size_t i;

	printf("eBPF program (insn cnt = %lu)\n", prog->insns_cnt);
	for (i = 0; i < prog->insns_cnt; i++) {
		struct bpf_insn insn = prog->insns[i];
		printf("(%03lu) code:0x%02x (m:%02x|s:%02x|c:%02x) dst:0x%01x "
		       "src:0x%01x off:0x%04x imm:0x%08x\n", i, insn.code,
		       BPF_MODE(insn.code), BPF_SIZE(insn.code),
		       BPF_CLASS(insn.code), insn.dst_reg, insn.src_reg,
		       insn.off, insn.imm);
	}
}

void ebpf_program_free(struct ebpf_program *prog)
{
	if (prog)
		free(prog->insns);
	free(prog);
}
