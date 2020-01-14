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


static int xdp_parse_run_order(const struct bpf_object *obj,
			       struct xdp_program *xdp_prog)
{

	const struct btf_type *t, *var, *def, *sec = NULL;
	int err, nr_types, i, j, vlen, mlen;
	const struct btf_var_secinfo *vi;
	const struct btf_var *var_extra;
	const struct btf_member *m;
	char struct_name[100];
	struct btf *btf;
	const char *name;

	if (!xdp_prog->prog)
		return -EINVAL;

	btf = bpf_object__btf(obj);
	if (!btf)
		return -EINVAL;

	err = check_snprintf(struct_name, sizeof(struct_name), "_%s",
			     bpf_program__name(xdp_prog->prog));
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
//		pr_warn("DATASEC '%s' not found.\n", XDP_RUN_ORDER_SEC);
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
//			pr_warn("map '%s': unexpected var kind %u.\n",
//				map_name, btf_kind(var));
			return -EINVAL;
		}
		if (var_extra->linkage != BTF_VAR_GLOBAL_ALLOCATED &&
		    var_extra->linkage != BTF_VAR_STATIC) {
//			pr_warn("map '%s': unsupported var linkage %u.\n",
//				map_name, var_extra->linkage);
			return -EOPNOTSUPP;
		}

		def = skip_mods_and_typedefs(btf, var->type, NULL);
		if (!btf_is_struct(def)) {
//			pr_warn("map '%s': unexpected def kind %u.\n",
//				map_name, btf_kind(var));
			return -EINVAL;
		}
		if (def->size > vi->size) {
//			pr_warn("map '%s': invalid def size.\n", map_name);
			return -EINVAL;
		}

		mlen = btf_vlen(def);
		m = btf_members(def);
		for (j = 0; j < mlen; j++, m++) {
			const char *mname = btf__name_by_offset(btf, m->name_off);
			unsigned int val, act;

			if (!mname) {
				//	pr_warn("map '%s': invalid field #%d.\n", map_name, i);
				return -EINVAL;
			}
			if (strcmp(mname, "priority")) {
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
				return -ENOTSUP;
			}
		}
		return 0;
	}

	return -ENOENT;
}

struct xdp_program *xdp_get_program(const struct bpf_object *obj,
				    const char *prog_name)
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

	xdp_prog = malloc(sizeof(*xdp_prog));
	if (!xdp_prog)
		return ERR_PTR(-ENOMEM);

	memset(xdp_prog, 0, sizeof(*xdp_prog));

	xdp_prog->prog = bpf_prog;
	err = xdp_parse_run_order(obj, xdp_prog);
	if (err)
		goto err;

	return xdp_prog;
err:
	free(xdp_prog);
	return ERR_PTR(err);
}
