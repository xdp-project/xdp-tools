// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/err.h> /* ERR_PTR */
#include <bpf/libbpf.h> /* ERR_PTR */
#include <bpf/btf.h> /* ERR_PTR */
#include <xdp/libxdp.h>
#include "logging.h"
#include "util.h"

#define XDP_RUN_ORDER_SEC ".xdp_run_order"

struct xdp_program {
	/* one of prog or prog_fd should be set */
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	struct btf *btf;
	int prog_fd;
	const char *prog_name;
	bool from_external_obj;
	unsigned int run_prio;
	unsigned int chain_call_actions; // bitmap
};


static const char *xdp_action_names[] = {
	[XDP_ABORTED] = "XDP_ABORTED",
	[XDP_DROP] = "XDP_DROP",
	[XDP_PASS] = "XDP_PASS",
	[XDP_TX] = "XDP_TX",
	[XDP_REDIRECT] = "XDP_REDIRECT",
};

static struct btf *xdp_program__btf(struct xdp_program *xdp_prog)
{
	return xdp_prog->btf;
}

static void set_chain_call_action(struct xdp_program *prog, unsigned int action,
				  bool value)
{
	if (value)
		prog->chain_call_actions |= (1<<action);
	else
		prog->chain_call_actions &= ~(1<<action);
}

bool xdp_program__chain_call_enabled(struct xdp_program *prog,
				     enum xdp_action action)
{
	return !!(prog->chain_call_actions & (1<<action));
}

unsigned int xdp_program__run_prio(struct xdp_program *prog)
{
	return prog->run_prio;
}

const char *xdp_program__name(struct xdp_program *prog)
{
	return prog->prog_name;
}

int xdp_program__print_chain_call_actions(struct xdp_program *prog,
					  char *buf,
					  size_t buf_len)
{
	bool first = true;
	char *pos = buf;
	size_t len = 0;
	int i;

	for (i = 0; i <= XDP_REDIRECT; i++) {
		if (xdp_program__chain_call_enabled(prog, i)) {
			if (!first) {
				*pos++ = ',';
				buf_len--;
			} else {
				first = false;
			}
			len = snprintf(pos, buf_len-len, "%s",
				       xdp_action_names[i]);
			pos += len;
			buf_len -= len;
		}
	}
	return 0;
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

static int xdp_parse_run_order(struct xdp_program *xdp_prog)
{

	const struct btf_type *t, *var, *def, *sec = NULL;
	struct btf *btf = xdp_program__btf(xdp_prog);
	int err, nr_types, i, j, vlen, mlen;
	const struct btf_var_secinfo *vi;
	const struct btf_var *var_extra;
	const struct btf_member *m;
	char struct_name[100];
	const char *name;

	if (!btf) {
		pr_debug("No BTF found for program\n");
		return -ENOENT;
	}

	err = check_snprintf(struct_name, sizeof(struct_name), "_%s",
			     xdp_program__name(xdp_prog));
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

	pr_debug("Couldn't find run order struct %s\n", struct_name);
	return -ENOENT;
}

struct xdp_program *xdp_program__new()
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

void xdp_program__free(struct xdp_program *xdp_prog)
{
	if (xdp_prog->prog_fd >= 0)
		close(xdp_prog->prog_fd);

	if (!xdp_prog->from_external_obj) {
		if (xdp_prog->bpf_obj)
			bpf_object__close(xdp_prog->bpf_obj);
		else if (xdp_prog->btf)
			btf__free(xdp_prog->btf);
	}
}

static struct xdp_program *xdp_program__from_obj(struct bpf_object *obj,
						 const char *prog_name,
						 bool external)
{
	struct xdp_program *xdp_prog;
	struct bpf_program *bpf_prog;
	int err;

	if (prog_name)
		bpf_prog = bpf_object__find_program_by_title(obj, prog_name);
	else
		bpf_prog = bpf_program__next(NULL, obj);

	if(!bpf_prog)
		return ERR_PTR(-ENOENT);

	xdp_prog = xdp_program__new();
	if (IS_ERR(xdp_prog))
		return xdp_prog;

	xdp_prog->bpf_prog = bpf_prog;
	xdp_prog->bpf_obj = obj;
	xdp_prog->btf = bpf_object__btf(obj);
	xdp_prog->from_external_obj = external;
	xdp_prog->prog_name = bpf_program__name(bpf_prog);

	err = xdp_parse_run_order(xdp_prog);
	if (err && err != -ENOENT)
		goto err;

	return xdp_prog;
err:
	free(xdp_prog);
	return ERR_PTR(err);
}

struct xdp_program *xdp_program__from_bpf_obj(struct bpf_object *obj,
					      const char *prog_name)
{
	return xdp_program__from_obj(obj, prog_name, true);
}

struct xdp_program *xdp_program__open_file(const char *filename,
					   const char *prog_name,
					   struct bpf_object_open_opts *opts)
{
	struct xdp_program *xdp_prog;
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open_file(filename, opts);
	err = libbpf_get_error(obj);
	if (err)
		return ERR_PTR(err);

	xdp_prog = xdp_program__from_obj(obj, prog_name, false);
	if (IS_ERR(xdp_prog))
		bpf_object__close(obj);

	return xdp_prog;
}

struct xdp_program *xdp_program__from_id(__u32 id)
{
	struct xdp_program *xdp_prog = NULL;
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	struct btf *btf = NULL;
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

	xdp_prog = xdp_program__new();
	if (IS_ERR(xdp_prog))
		return xdp_prog;

	xdp_prog->prog_name = strdup(info.name);
	if (!xdp_prog->prog_name) {
		err = -ENOMEM;
		pr_warn("failed to strdup program title");
		goto err;
	}

	if (info.btf_id) {
		err = btf__get_from_id(info.btf_id, &btf);
		if (err) {
			pr_warn("Couldn't get BTF for ID %ul\n", info.btf_id);
			goto err;
		}
	}

	xdp_prog->prog_fd = fd;
	xdp_prog->btf = btf;

	err = xdp_parse_run_order(xdp_prog);
	if (err && err != -ENOENT)
		goto err;

	return xdp_prog;

err:
	free(xdp_prog);
	btf__free(btf);
	return ERR_PTR(err);
}
