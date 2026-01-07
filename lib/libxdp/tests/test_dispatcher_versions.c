/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/err.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_utils.h"
#include "../libxdp_internal.h"
#include "xdp_dispatcher.h"

#include <xdp/libxdp.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BPFFS_DIR "/sys/fs/bpf/xdp"

#define PROG_RUN_PRIO 42
#define PROG_CHAIN_CALL_ACTIONS (1 << XDP_DROP)
#define DISPATCHER_V1_FILE "xdp_dispatcher_v1.o"
#define DISPATCHER_V2_FILE "xdp_dispatcher_v2.o"

#ifndef HAVE_LIBBPF_BPF_OBJECT__NEXT_MAP
static struct bpf_map *bpf_object__next_map(const struct bpf_object *obj,
					    const struct bpf_map *map)
{
	return bpf_map__next(map, obj);
}
#endif

static void print_test_result(const char *func, int ret)
{
	fflush(stderr);
	fprintf(stderr, "%s:\t%s\n", func, ret ? "FAILED" : "PASSED");
	fflush(stdout);
}

int get_prog_id(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int err;

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &len);
	if (err)
		return -errno;

	return info.id;
}

static char* get_dispatcher_file(unsigned int dispatcher_version)
{
	switch (dispatcher_version) {
	case XDP_DISPATCHER_VERSION_V1:
		return DISPATCHER_V1_FILE;

	case XDP_DISPATCHER_VERSION_V2:
		return DISPATCHER_V2_FILE;

	default:
		break;
	}
	return NULL;
}

int load_dispatcher(int ifindex, unsigned int dispatcher_version)
{
	struct xdp_dispatcher_config_v1 dispatcher_config_v1 = {};
	struct xdp_dispatcher_config_v2 dispatcher_config_v2 = {};
	char *dispatcher_file = get_dispatcher_file(dispatcher_version);
	struct bpf_object *obj_dispatcher, *obj_prog = NULL;
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	struct bpf_program *dispatcher_prog, *xdp_prog;
	int ret = 0, btf_id, lfd = -1, dispatcher_id;
	char pin_path[PATH_MAX], buf[PATH_MAX];
	const char *attach_func = "prog0";
	struct bpf_map *map;

	if (!ifindex || !dispatcher_file)
		return -ENOENT;

	obj_dispatcher = open_bpf_file(dispatcher_file, NULL);
	if (IS_ERR_OR_NULL(obj_dispatcher))
		return -errno;

	btf_id = btf__find_by_name_kind(bpf_object__btf(obj_dispatcher),
					attach_func, BTF_KIND_FUNC);
	if (btf_id <= 0) {
		ret = -ENOENT;
		goto out;
	}
	opts.target_btf_id = btf_id;

	map = bpf_object__next_map(obj_dispatcher, NULL);
	if (!map) {
		ret = -ENOENT;
		goto out;
	}

	dispatcher_prog = bpf_object__find_program_by_name(obj_dispatcher,
							   "xdp_dispatcher");
	if (!dispatcher_prog) {
		ret = -errno;
		goto out;
	}

	switch (dispatcher_version) {
	case XDP_DISPATCHER_VERSION_V1:
		dispatcher_config_v1.num_progs_enabled = 1;
		dispatcher_config_v1.chain_call_actions[0] = PROG_CHAIN_CALL_ACTIONS;
		dispatcher_config_v1.run_prios[0] = PROG_RUN_PRIO;

		ret = bpf_map__set_initial_value(map, &dispatcher_config_v1,
						 sizeof(dispatcher_config_v1));
		break;

	case XDP_DISPATCHER_VERSION_V2:
		dispatcher_config_v2.magic = XDP_DISPATCHER_MAGIC;
		dispatcher_config_v2.num_progs_enabled = 1;
		dispatcher_config_v2.chain_call_actions[0] = PROG_CHAIN_CALL_ACTIONS;
		dispatcher_config_v2.run_prios[0] = PROG_RUN_PRIO;
		dispatcher_config_v2.is_xdp_frags = 0;
		dispatcher_config_v2.program_flags[0] = 0;
		dispatcher_config_v2.dispatcher_version = XDP_DISPATCHER_VERSION_V2;

		ret = bpf_map__set_initial_value(map, &dispatcher_config_v2,
						 sizeof(dispatcher_config_v2));
	}

	if (ret)
		goto out;

	ret = bpf_object__load(obj_dispatcher);
	if (ret)
		goto out;

	dispatcher_id = get_prog_id(bpf_program__fd(dispatcher_prog));
	if (dispatcher_id < 0) {
		ret = dispatcher_id;
		goto out;
	}

	obj_prog = open_bpf_file("xdp_pass.o", NULL);
	if (!obj_prog) {
		ret = -errno;
		goto out;
	}

	xdp_prog = bpf_object__find_program_by_name(obj_prog, "xdp_pass");
	if (!xdp_prog) {
		ret = -errno;
		goto out;
	}

	ret = bpf_program__set_attach_target(xdp_prog,
					     bpf_program__fd(dispatcher_prog),
					     attach_func);
	if (ret)
		goto out;

	bpf_program__set_type(xdp_prog, BPF_PROG_TYPE_EXT);
	bpf_program__set_expected_attach_type(xdp_prog, 0);

	ret = bpf_object__load(obj_prog);
	if (ret)
		goto out;

	lfd = bpf_link_create(bpf_program__fd(xdp_prog),
			      bpf_program__fd(dispatcher_prog), 0, &opts);
	if (lfd < 0) {
		ret = -errno;
		goto out;
	}

	ret = try_snprintf(pin_path, sizeof(pin_path), "%s/dispatch-%d-%d",
			   BPFFS_DIR, ifindex, dispatcher_id);
	if (ret)
		goto out;

	ret = mkdir(BPFFS_DIR, S_IRWXU);
	if (ret && errno != EEXIST) {
		ret = -errno;
		printf("mkdir err (%s): %s\n", BPFFS_DIR, strerror(-ret));
		goto out;
	}

	ret = mkdir(pin_path, S_IRWXU);
	if (ret) {
		ret = -errno;
		printf("mkdir err (%s): %s\n", pin_path, strerror(-ret));
		goto out;
	}

	ret = try_snprintf(buf, sizeof(buf), "%s/prog0-link", pin_path);
	if (ret)
		goto err_unpin;

	ret = bpf_obj_pin(lfd, buf);
	if (ret)
		goto err_unpin;

	ret = try_snprintf(buf, sizeof(buf), "%s/prog0-prog", pin_path);
	if (ret)
		goto err_unpin;

	ret = bpf_obj_pin(bpf_program__fd(xdp_prog), buf);
	if (ret)
		goto err_unpin;

	ret = xdp_attach_fd(bpf_program__fd(dispatcher_prog), -1, ifindex,
			    XDP_MODE_NATIVE);
	if (ret)
		goto err_unpin;

out:
	if (lfd >= 0)
		close(lfd);
	bpf_object__close(obj_dispatcher);
	bpf_object__close(obj_prog);
	return ret;

err_unpin:
	if (!try_snprintf(buf, sizeof(buf), "%s/prog0-link", pin_path))
		unlink(buf);
	if (!try_snprintf(buf, sizeof(buf), "%s/prog0-prog", pin_path))
		unlink(buf);
	rmdir(pin_path);
	goto out;
}

int check_old_dispatcher(int ifindex, unsigned int dispatcher_version)
{
	struct xdp_multiprog *mp = NULL;
	struct xdp_program *xdp_prog;
	char buf[100];
	int ret;

	ret = load_dispatcher(ifindex, dispatcher_version);
	if (ret)
		goto out;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	ret = libxdp_get_error(mp);
	if (ret)
		goto out;

	if (xdp_multiprog__is_legacy(mp)) {
		printf("Got unexpected legacy multiprog\n");
		ret = -EINVAL;
		goto out;
	}

	if (xdp_multiprog__program_count(mp) != 1) {
		printf("Expected 1 attached program, got %d\n",
		       xdp_multiprog__program_count(mp));
		ret = -EINVAL;
		goto out;
	}

	xdp_prog = xdp_multiprog__next_prog(NULL, mp);
	if (!xdp_prog) {
		ret = -errno;
		goto out;
	}

	if (strcmp(xdp_program__name(xdp_prog), "xdp_pass")) {
		printf("Expected xdp_pass program, got %s\n",
		       xdp_program__name(xdp_prog));
		ret = -EINVAL;
		goto out;
	}

	if (xdp_program__run_prio(xdp_prog) != PROG_RUN_PRIO) {
		printf("Expected run prio %d got %d\n", PROG_RUN_PRIO,
		       xdp_program__run_prio(xdp_prog));
		ret = -EINVAL;
		goto out;
	}

	ret = xdp_program__print_chain_call_actions(xdp_prog, buf, sizeof(buf));
	if (ret)
		goto out;

	if (strcmp(buf, "XDP_DROP")) {
		printf("Expected actions XDP_PASS, got %s\n", buf);
		ret = -EINVAL;
		goto out;
	}

        DECLARE_LIBXDP_OPTS(xdp_program_opts, pass_opts);
        pass_opts.prog_name = "xdp_pass";
        pass_opts.find_filename = "xdp-dispatcher.o";
        xdp_prog = xdp_program__create(&pass_opts);
        ret = libxdp_get_error(xdp_prog);
        if (ret)
                goto out;

	ret = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_NATIVE, 0);
	xdp_program__close(xdp_prog);
	if (!ret) {
		printf("Shouldn't have been able to attach a new program to ifindex!\n");
		ret = -EINVAL;
		goto out;
	}
	ret = 0;

out:
	if (mp)
		xdp_multiprog__detach(mp);
	xdp_multiprog__close(mp);
	return ret;
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <ifname>\n", progname);
	exit(EXIT_FAILURE);
}

int check_old_dispatcher_v1(int ifindex)
{
	int ret = check_old_dispatcher(ifindex, XDP_DISPATCHER_VERSION_V1);
	print_test_result(__func__, ret);
	return ret;
}

int check_old_dispatcher_v2(int ifindex)
{
	int ret = check_old_dispatcher(ifindex, XDP_DISPATCHER_VERSION_V2);
	print_test_result(__func__, ret);
	return ret;
}

int main(int argc, char **argv)
{
	int ifindex, ret;
	char *envval;

	envval = secure_getenv("VERBOSE_TESTS");

	silence_libbpf_logging();
	if (envval && envval[0] == '1')
		verbose_libxdp_logging();
	else
		silence_libxdp_logging();

	if (argc != 2)
		usage(argv[0]);

	ifindex = if_nametoindex(argv[1]);

	ret = check_old_dispatcher_v1(ifindex);
	ret = check_old_dispatcher_v2(ifindex) || ret;

	return ret;
}
