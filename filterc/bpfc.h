/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPFC_H_
#define _BPFC_H_

struct cbpf_insn;
struct cbpf_program;
struct ebpf_program;

char *bpfc_geterr();

struct cbpf_program *cbpf_program_from_filter(char*);
void cbpf_program_dump(struct cbpf_program*);
void cbpf_program_free(struct cbpf_program*);

struct ebpf_program *ebpf_program_from_cbpf(struct cbpf_program*);
int ebpf_program_write_elf(struct ebpf_program*, char *);
void ebpf_program_dump(struct ebpf_program*);
void ebpf_program_free(struct ebpf_program*);

#endif /* _BPFC_H_ */
