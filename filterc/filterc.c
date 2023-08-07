/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>

#include "logging.h"
#include "params.h"

#include "bpfc.h"

#define PROG_NAME "filterc"

static const struct filteropt {
	char *output;
	char *progname;
	char *filter;
} filteropt_defaults = {
};
struct filteropt cfg_filteropt;

static struct prog_option filterc_options[] = {
	DEFINE_OPTION("output", OPT_STRING, struct filteropt, output,
		      .short_opt = 'o',
		      .required = true,
		      .metavar = "<file>",
		      .help = "Output compiled object to <file>"),
	DEFINE_OPTION("program-name", OPT_STRING, struct filteropt, progname,
		      .short_opt = 'n',
		      .metavar = "<name>",
		      .help = "Name of the program in the BPF object file "\
			      "(default: " BPFC_PROG_SYM_NAME ")"),
	DEFINE_OPTION("filter", OPT_STRING, struct filteropt, filter,
		      .required = true,
		      .positional = true,
		      .metavar = "<filter>",
		      .help = "pcap-filter(7) string to compile"),
	END_OPTIONS
};

int main(int argc, char **argv)
{
	struct cbpf_program *cbpf_prog = NULL;
	struct ebpf_program *ebpf_prog = NULL;
	int err, rc = EXIT_FAILURE;

	if (parse_cmdline_args(argc, argv, filterc_options, &cfg_filteropt,
			       sizeof(cfg_filteropt), PROG_NAME, PROG_NAME,
			       "Compile pcap-filter expressions to eBPF object files",
			       &filteropt_defaults) != 0)
		goto out;

	cbpf_prog = cbpf_program_from_filter(cfg_filteropt.filter);
	if (!cbpf_prog) {
		pr_warn("Failed to compile filter\n");
		goto out;
	}

	cbpf_program_dump(cbpf_prog);

	ebpf_prog = ebpf_program_from_cbpf(cbpf_prog);
	if (!ebpf_prog) {
		pr_warn("Failed to convert cBPF to eBPF: %s\n", bpfc_geterr());
		goto out;
	}

	ebpf_program_dump(ebpf_prog);

	pr_info("Writing BPF object file (ELF)\n");
	LIBBPF_OPTS(elf_write_opts, write_opts,
		    .progname = cfg_filteropt.progname,
		    .path = cfg_filteropt.output);
	err = ebpf_program_write_elf(ebpf_prog, &write_opts);
	if (err) {
		pr_warn("Failed to write BPF object in ELF format: %s\n",
			bpfc_geterr());
		rc = err;
		goto out;
	}

	rc = EXIT_SUCCESS;

out:
	if (ebpf_prog)
		ebpf_program_free(ebpf_prog);
	if (cbpf_prog)
		cbpf_program_free(cbpf_prog);
	return rc;
}
