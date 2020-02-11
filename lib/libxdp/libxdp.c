// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#include <string.h>
#include <errno.h>
#include <linux/err.h> /* ERR_PTR */
#include <bpf/libbpf.h> /* ERR_PTR */
#include <bpf/btf.h> /* ERR_PTR */
#include <xdp/libxdp.h>
#include "logging.h"
#include "util.h"

#define XDP_RUN_ORDER_SEC ".xdp_run_order"

static const char *xdp_action_names[] = {
	[XDP_ABORTED] = "XDP_ABORTED",
	[XDP_DROP] = "XDP_DROP",
	[XDP_PASS] = "XDP_PASS",
	[XDP_TX] = "XDP_TX",
	[XDP_REDIRECT] = "XDP_REDIRECT",
};

static void set_chain_call_action(struct xdp_program *prog, unsigned int action,
				  bool value)
{
	if (value)
		prog->chain_call_actions |= (1<<action);
	else
		prog->chain_call_actions &= ~(1<<action);
}

static const struct btf_type *
skip_mods_and_typedefs(const struct btf *btf, __u32 id, __u32 *res_id)
{
	const struct btf_type *t = btf__type_by_id(btf, id);

	if (res_id)
		*res_id = id;

	while (btf_is_mod(t) || btf_is_typedef(t)) {
		if (res_id)
			*res_id = t->type;
		t = btf__type_by_id(btf, t->type);
	}

	return t;
}

static bool get_field_int(const char *prog_name, const struct btf *btf,
			  const struct btf_type *def,
			  const struct btf_member *m, __u32 *res)
{
	const struct btf_type *t = skip_mods_and_typedefs(btf, m->type, NULL);
	const char *name = btf__name_by_offset(btf, m->name_off);
	const struct btf_array *arr_info;
	const struct btf_type *arr_t;

	if (!btf_is_ptr(t)) {
		pr_warn("prog '%s': attr '%s': expected PTR, got %u.\n",
			prog_name, name, btf_kind(t));
		return false;
	}

	arr_t = btf__type_by_id(btf, t->type);
	if (!arr_t) {
		pr_warn("prog '%s': attr '%s': type [%u] not found.\n",
			prog_name, name, t->type);
		return false;
	}
	if (!btf_is_array(arr_t)) {
		pr_warn("prog '%s': attr '%s': expected ARRAY, got %u.\n",
			prog_name, name, btf_kind(arr_t));
		return false;
	}
	arr_info = btf_array(arr_t);
	*res = arr_info->nelems;
	return true;
}

static bool get_xdp_action(const char *act_name, unsigned int *act)
{
	const char **name = xdp_action_names;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(xdp_action_names); i++, name++) {
		if (!strcmp(act_name, *name)) {
			*act = i;
			return true;
		}
	}
	return false;
}

static int xdp_program_print_name(char *buf, size_t buf_len, const char *fmt,
				  struct xdp_program *xdp_prog)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	const char *prog_name;
	int err;

	if (xdp_prog->prog) {
		prog_name = bpf_program__name(xdp_prog->prog);
	} else if (xdp_prog->prog_fd > -1) {
		err = bpf_obj_get_info_by_fd(xdp_prog->prog_fd, &info, &len);
		if (err) {
			err = -errno;
			pr_warn("couldn't get program info: %s", strerror(-err));
			return err;
		}
		prog_name = info.name;
	}
	else
		return -EINVAL;

	return check_snprintf(buf, buf_len, fmt, prog_name);
}


static int xdp_parse_run_order(const struct btf *btf,
			       struct xdp_program *xdp_prog)
{

	const struct btf_type *t, *var, *def, *sec = NULL;
	int err, nr_types, i, j, vlen, mlen;
	const struct btf_var_secinfo *vi;
	const struct btf_var *var_extra;
	const struct btf_member *m;
	char struct_name[100];
	const char *name;

	err = xdp_program_print_name(struct_name, sizeof(struct_name), "_%s",
				     xdp_prog);
	if (err)
		return err;

	nr_types = btf__get_nr_types(btf);
	for (i = 1; i <= nr_types; i++) {
		t = btf__type_by_id(btf, i);
		if (!btf_is_datasec(t))
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (strcmp(name, XDP_RUN_ORDER_SEC) == 0) {
			sec = t;
			break;
		}
	}

	if (!sec) {
		pr_debug("DATASEC '%s' not found.\n", XDP_RUN_ORDER_SEC);
		return -ENOENT;
	}

	vlen = btf_vlen(sec);
	vi = btf_var_secinfos(sec);
	for (i = 0; i < vlen; i++, vi++) {
		var = btf__type_by_id(btf, vi->type);
		var_extra = btf_var(var);
		name = btf__name_by_offset(btf, var->name_off);

		if (strcmp(name, struct_name))
			continue;

		if (!btf_is_var(var)) {
			pr_warn("struct '%s': unexpected var kind %u.\n",
				name, btf_kind(var));
			return -EINVAL;
		}
		if (var_extra->linkage != BTF_VAR_GLOBAL_ALLOCATED &&
		    var_extra->linkage != BTF_VAR_STATIC) {
			pr_warn("struct '%s': unsupported var linkage %u.\n",
				name, var_extra->linkage);
			return -EOPNOTSUPP;
		}

		def = skip_mods_and_typedefs(btf, var->type, NULL);
		if (!btf_is_struct(def)) {
			pr_warn("struct '%s': unexpected def kind %u.\n",
				name, btf_kind(var));
			return -EINVAL;
		}
		if (def->size > vi->size) {
			pr_warn("struct '%s': invalid def size.\n", name);
			return -EINVAL;
		}

		mlen = btf_vlen(def);
		m = btf_members(def);
		for (j = 0; j < mlen; j++, m++) {
			const char *mname = btf__name_by_offset(btf, m->name_off);
			unsigned int val, act;

			if (!mname) {
				pr_warn("struct '%s': invalid field #%d.\n", name, i);
				return -EINVAL;
			}
			if (!strcmp(mname, "priority")) {
				if (!get_field_int(struct_name, btf, def, m,
						   &xdp_prog->run_prio))
					return -EINVAL;
				continue;
			} else if(get_xdp_action(mname, &act)) {
				if (!get_field_int(struct_name, btf, def, m,
						   &val))
					return -EINVAL;
				set_chain_call_action(xdp_prog, act, val);
			} else {
				pr_warn("Invalid mname: %s\n", mname);
				return -ENOTSUP;
			}
		}
		return 0;
	}

	return -ENOENT;
}

static struct xdp_program *xdp_program_new()
{
	struct xdp_program *xdp_prog;

	xdp_prog = malloc(sizeof(*xdp_prog));
	if (!xdp_prog)
		return ERR_PTR(-ENOMEM);

	memset(xdp_prog, 0, sizeof(*xdp_prog));

	xdp_prog->prog_fd = -1;
	xdp_prog->run_prio = XDP_DEFAULT_RUN_PRIO;
	xdp_prog->chain_call_actions = XDP_DEFAULT_CHAIN_CALL_ACTIONS;

	return xdp_prog;
}

struct xdp_program *xdp_get_program(const struct bpf_object *obj,
				    const char *prog_name)
{
	struct xdp_program *xdp_prog;
	struct bpf_program *bpf_prog;
	struct btf *btf;
	int err;

	if (prog_name)
		bpf_prog = bpf_object__find_program_by_title(obj, prog_name);
	else
		bpf_prog = bpf_program__next(NULL, obj);

	if(!bpf_prog)
		return ERR_PTR(-ENOENT);

	xdp_prog = xdp_program_new();
	if (IS_ERR(xdp_prog))
		return xdp_prog;

	xdp_prog->prog = bpf_prog;
	btf = bpf_object__btf(obj);
	if (btf) {
		err = xdp_parse_run_order(btf, xdp_prog);
		if (err && err != -ENOENT)
			goto err;
	}

	return xdp_prog;
err:
	free(xdp_prog);
	return ERR_PTR(err);
}

struct xdp_program *xdp_get_program_by_id(__u32 id)
{
	struct xdp_program *xdp_prog = NULL;
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	struct btf *btf;
	int fd, err;

	fd = bpf_prog_get_fd_by_id(id);
	if (fd < 0) {
		pr_warn("couldn't get program fd: %s", strerror(errno));
		err = -errno;
		goto err;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (err) {
		pr_warn("couldn't get program info: %s", strerror(errno));
		err = -errno;
		goto err;
	}

	xdp_prog = xdp_program_new();
	if (IS_ERR(xdp_prog))
		return xdp_prog;

	xdp_prog->prog_fd = fd;

	if (info.btf_id) {
		err = btf__get_from_id(info.btf_id, &btf);
		if (err) {
			pr_warn("Couldn't get BTF for ID %ul\n", info.btf_id);
			goto err;
		}
		err = xdp_parse_run_order(btf, xdp_prog);
		if (err && err != -ENOENT)
			goto err;
	}

	return xdp_prog;

err:
	free(xdp_prog);
	return ERR_PTR(err);
}
