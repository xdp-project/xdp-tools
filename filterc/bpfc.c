/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/filter.h>

#include <linux/bpf.h>

// We need the bpf_insn and bpf_program definitions from libpcap, but they
// conflict with the Linux/libbpf definitions. Rename the libpcap structs to
// prevent the conflicts.
#define bpf_insn cbpf_insn
#define bpf_program cbpf_program
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#undef bpf_insn
#undef bpf_program

#include "filter.h"
#include "bpfc.h"

#define BPFC_DEFAULT_SNAP_LEN 262144
#define BPFC_ERRBUFF_SZ 256

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
 */

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
		/* All programs must keep CTX in callee saved BPF_REG_CTX.
		 * In eBPF case it's done by the compiler, here we need to
		 * do this ourself. Initial CTX is present in BPF_REG_ARG1.
		 */
		*new_insn++ = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
	} else {
		new_insn += 1;
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
		if (target >= (int)cbpf_prog->bf_len || target < 0) {	\
			bpfc_error("insn %d: Invalid jump target", i);\
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
			if (BPF_RVAL(fp->code) == BPF_K)
				*insn++ = BPF_MOV32_IMM(BPF_REG_0, fp->k);

			*insn++ = BPF_EXIT_INSN();
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
