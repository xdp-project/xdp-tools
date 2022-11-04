/* SPDX-License-Identifier: GPL-2.0 */

struct cbpf_insn;
struct cbpf_program;

struct cbpf_program *cbpf_program_from_filter(char*);
void cbpf_program_dump(struct cbpf_program*);
void cbpf_program_free(struct cbpf_program*);
