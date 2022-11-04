/* SPDX-License-Identifier: GPL-2.0 */

#include <stdlib.h>

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

#define DEFAULT_SNAP_LEN 262144

struct cbpf_program *cbpf_program_from_filter(char *filter)
{
	pcap_t *pcap = NULL;
	struct cbpf_program *prog = NULL;
	int err;

	pcap = pcap_open_dead(DLT_EN10MB, DEFAULT_SNAP_LEN);
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
	bpf_dump(prog, 1);
}

void cbpf_program_free(struct cbpf_program *prog)
{
	pcap_freecode(prog);
	free(prog);
}
