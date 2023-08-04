/* SPDX-License-Identifier: GPL-2.0 */

#include <stdlib.h>

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

struct ebpf_program *ebpf_program_from_cbpf(struct cbpf_program *cbpf_prog)
{
	struct ebpf_program *prog = NULL;

	prog = malloc(sizeof(*prog));
	if (!prog) {
		goto error;
	}

	prog->insns_cnt = cbpf_prog->bf_len;

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
