/* SPDX-License-Identifier: GPL-2.0 */
#include <errno.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <arpa/inet.h>
#include <linux/in.h>

#include "params.h"
#include "util.h"
#include "logging.h"

#include "../bpfc.h"

#define PROG_NAME "test_bpfc"

#define TEST(_tn) \
	{ .name = "test_"textify(_tn), .func = do_test_##_tn, .no_cfg = true }
#define TEST_FUNC(_tn) \
	int do_test_##_tn(__unused const void *cfg, __unused const char *pin_root_path)

#define TMP_SUFFIX ".bpf.o"
#define TEST_PROG_NAME "filterc_test_prog"

static struct bpf_object *compile_filter(char *filter)
{
	struct cbpf_program *cbpf_prog;
	struct ebpf_program *ebpf_prog;
	struct bpf_object *bpf_obj;
	char fname[] = "/tmp/"PROG_NAME"_XXXXXX"TMP_SUFFIX;
	int err, fd;

	fd = mkstemps(fname, strlen(TMP_SUFFIX));
	if (fd < 0) {
		printf("Failed to create temp file\n");
		return NULL;
	}


	cbpf_prog = cbpf_program_from_filter(filter);
	if (!cbpf_prog) {
		printf("Failed to compile filter.\n");
		return NULL;
	}

	ebpf_prog = ebpf_program_from_cbpf(cbpf_prog);
	if (!ebpf_prog) {
		printf("Failed to convert cBPF to eBPF: %s\n", bpfc_geterr());
		return NULL;
	}

	LIBBPF_OPTS(elf_write_opts, write_opts,
		    .fd = fd,
		    .progname = TEST_PROG_NAME);
	err = ebpf_program_write_elf(ebpf_prog, &write_opts);
	if (err) {
		printf("Failed to write BPF object in ELF format: %s\n",
			bpfc_geterr());
		return NULL;
	}

	bpf_obj = bpf_object__open(fname);
	if (!bpf_obj) {
		err = errno;
		printf("Failed to open BPF object: %s (%d)\n", strerror(err), err);
		return NULL;
	}

	err = unlink(fname);
	if (err) {
		err = errno;
		printf("Failed to unlink temp file '%s': %s (%d)\n",
		       fname, strerror(err), err);
		return NULL;
	}

	return bpf_obj;
}

int build_udp_packet(void *pkt, int len, int dst_port)
{
	struct ethhdr *eh = pkt;
	struct iphdr *iph = (struct iphdr *)(eh + 1);
	struct udphdr *udph = (struct udphdr *)(iph + 1);

	memset(pkt, 0, len);

	eh->h_proto = htons(ETH_P_IP);

	iph->protocol = IPPROTO_UDP;
	iph->ihl = 5;

	udph->source = htons(54321);
	udph->dest = htons(dst_port);

	return 0;
}

TEST_FUNC(standalone)
{
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;
	int err, prog_fd;
	int len = 128;
	void *pkt = malloc(len);

	bpf_obj = compile_filter("udp port 53");
	if (!bpf_obj) {
		printf("Failed to compile and open filter\n");
		return 1;
	}

	err = bpf_object__load(bpf_obj);
	if (err) {
		printf("Failed to load bpf object\n");
		return 1;
	}

	bpf_prog = bpf_object__find_program_by_name(bpf_obj, TEST_PROG_NAME);
	if (!bpf_prog) {
		printf("Failed to find bpf program in object\n");
		return 1;
	}
	prog_fd = bpf_program__fd(bpf_prog);

	err = build_udp_packet(pkt, len, 53);
	if (err) {
		printf("Failed to build packet (%d)\n", err);
		return 1;
	}
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, test_opts,
			    .data_in = pkt,
			    .data_size_in = len);
	err = bpf_prog_test_run_opts(prog_fd, &test_opts);
	if (err) {
		printf("Failed to run bpf prog (%d)\n", err);
		return 1;
	}
	if (test_opts.retval != XDP_PASS) {
		printf("Unexpected return value %d, expected %d\n",
		       test_opts.retval, XDP_PASS);
		return 1;
	}

	err = build_udp_packet(pkt, len, 123);
	if (err) {
		printf("Failed to build packet (%d)\n", err);
		return 1;
	}
	err = bpf_prog_test_run_opts(prog_fd, &test_opts);
	if (err) {
		printf("Failed to run bpf prog (%d)\n", err);
		return 1;
	}
	if (test_opts.retval != XDP_DROP) {
		printf("Unexpected return value %d, expected %d\n",
		       test_opts.retval, XDP_DROP);
		return 1;
	}

	free(pkt);
	return 0;
}

static const struct prog_command cmds[] = {
	TEST(standalone),
	END_COMMANDS
};

int main(int argc, char **argv)
{
	check_bpf_environ();
	set_log_level(LOG_VERBOSE);


	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 0, PROG_NAME, false);
	return -1;
}
