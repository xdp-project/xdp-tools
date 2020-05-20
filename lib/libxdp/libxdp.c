// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * XDP management utility functions
 *
 * Copyright (C) 2020 Toke Høiland-Jørgensen <toke@redhat.com>
 */

#define _GNU_SOURCE

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <dirent.h>

#include <linux/err.h> /* ERR_PTR */
#include <linux/if_link.h>
#include <linux/magic.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <xdp/libxdp.h>
#include <xdp/prog_dispatcher.h>
#include "logging.h"

#define XDP_RUN_CONFIG_SEC ".xdp_run_config"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct xdp_program {
	/* one of prog or prog_fd should be set */
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	struct btf *btf;
	int prog_fd;
	int link_fd;
	char *prog_name;
	char *attach_name;
	__u8 prog_tag[BPF_TAG_SIZE];
	__u32 prog_id;
	__u64 load_time;
	bool from_external_obj;
	unsigned int run_prio;
	unsigned int chain_call_actions; // bitmap

	/* for building list of attached programs to multiprog */
	struct xdp_program *next;
};

struct xdp_multiprog {
	struct xdp_dispatcher_config config;
	struct xdp_program *main_prog;  // dispatcher or legacy prog pointer
	struct xdp_program *first_prog; // uses xdp_program->next to build a list
	size_t num_links;
	bool is_loaded;
	bool is_legacy;
	enum xdp_attach_mode attach_mode;
};


static const char *xdp_action_names[] = {
	[XDP_ABORTED] = "XDP_ABORTED",
	[XDP_DROP] = "XDP_DROP",
	[XDP_PASS] = "XDP_PASS",
	[XDP_TX] = "XDP_TX",
	[XDP_REDIRECT] = "XDP_REDIRECT",
};

static int xdp_multiprog__attach(struct xdp_multiprog *old_mp,
				 struct xdp_multiprog *mp,
				 int ifindex, enum xdp_attach_mode mode);
static struct xdp_multiprog *
xdp_multiprog__generate(struct xdp_program **progs,
			size_t num_progs);
static int xdp_multiprog__pin(struct xdp_multiprog *mp);
static int xdp_multiprog__unpin(struct xdp_multiprog *mp);


long libxdp_get_error(const void *ptr)
{
	return libbpf_get_error(ptr);
}

int libxdp_strerror(int err, char *buf, size_t size)
{
	return libbpf_strerror(err, buf, size);
}

static int try_snprintf(char *buf, size_t buf_len, const char *format, ...)
{
	va_list args;
	int len;

	va_start(args, format);
	len = vsnprintf(buf, buf_len, format, args);
	va_end(args);

	if (len < 0)
		return -EINVAL;
	else if ((size_t)len >= buf_len)
		return -ENAMETOOLONG;

	return 0;
}

static bool bpf_is_valid_mntpt(const char *mnt, unsigned long magic)
{
	struct statfs st_fs;

	if (statfs(mnt, &st_fs) < 0)
		return false;
	if ((unsigned long)st_fs.f_type != magic)
		return false;

	return true;
}

static const char *bpf_find_mntpt_single(unsigned long magic, char *mnt,
					 int len, const char *mntpt)
{
	if (bpf_is_valid_mntpt(mntpt, magic)) {
		strncpy(mnt, mntpt, len-1);
		mnt[len-1] = '\0';
		return mnt;
	}

	return NULL;
}

static const char *find_bpffs()
{
	static bool bpf_mnt_cached = false;
	static char bpf_wrk_dir[PATH_MAX];
	static const char *mnt = NULL;
	char *envdir;

	if (bpf_mnt_cached)
		return mnt;

	envdir = secure_getenv(XDP_BPFFS_ENVVAR);
	mnt = bpf_find_mntpt_single(BPF_FS_MAGIC,
				    bpf_wrk_dir,
				    sizeof(bpf_wrk_dir),
				    envdir ?: BPF_DIR_MNT);
	if (!mnt)
		pr_warn("No bpffs found at %s\n", envdir ?: BPF_DIR_MNT);
	else
		bpf_mnt_cached = 1;

	return mnt;
}

static const char *get_bpffs_dir()
{
	static char bpffs_dir[PATH_MAX];
	static bool dir_cached = false;
	static const char *dir;
	const char *parent;
	int err;

	if (dir_cached)
		return dir;

	parent = find_bpffs();
	if (!parent) {
		err = -ENOENT;
		goto err;
	}

	err = try_snprintf(bpffs_dir, sizeof(bpffs_dir), "%s/xdp", parent);
	if (err)
		goto err;

	err = mkdir(bpffs_dir, S_IRWXU);
	if (err && errno != EEXIST) {
		err = -errno;
		goto err;
	}
	dir = bpffs_dir;
	dir_cached = true;
	return dir;
err:
	return ERR_PTR(err);
}

static int xdp_lock_acquire()
{
	int lock_fd, err;
	const char *dir;

	dir = get_bpffs_dir();
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	lock_fd = open(dir, O_DIRECTORY);
	if (lock_fd < 0) {
		err = -errno;
		pr_warn("Couldn't open lock directory at %s: %s\n",
			dir, strerror(-err));
		return err;
	}

	err = flock(lock_fd, LOCK_EX);
	if (err) {
		err = -errno;
		pr_warn("Couldn't flock fd %d: %s\n", lock_fd, strerror(-err));
		close(lock_fd);
		return err;
	}

	pr_debug("Acquired lock from %s with fd %d\n", dir, lock_fd);
	return lock_fd;
}

static int xdp_lock_release(int lock_fd)
{
	int err;

	err = flock(lock_fd, LOCK_UN);
	if (err) {
		err = -errno;
		pr_warn("Couldn't unlock fd %d: %s\n", lock_fd, strerror(-err));
	} else {
		pr_debug("Released lock fd %d\n", lock_fd);
	}
	close(lock_fd);
	return err;
}

const struct btf *xdp_program__btf(struct xdp_program *xdp_prog)
{
	if (!xdp_prog)
		return NULL;

	return xdp_prog->btf;
}

bool xdp_program__is_attached(const struct xdp_program *xdp_prog, int ifindex)
{
	struct xdp_program *prog = NULL;
	struct xdp_multiprog *mp;
	bool ret = false;

	if (!xdp_prog || !xdp_prog->prog_id)
		return false;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (IS_ERR_OR_NULL(mp))
		return false;

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		if (xdp_program__id(prog) == xdp_program__id(xdp_prog))
			ret = true;
		goto out;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
		if (xdp_program__id(prog) == xdp_program__id(xdp_prog)) {
			ret = true;
			break;
		}
	}

out:
	xdp_multiprog__close(mp);
	return ret;
}

int xdp_program__set_chain_call_enabled(struct xdp_program *prog,
					unsigned int action, bool enabled)
{
	if (!prog || prog->prog_fd || action >= XDP_DISPATCHER_RETVAL)
		return -EINVAL;

	if (enabled)
		prog->chain_call_actions |= (1U << action);
	else
		prog->chain_call_actions &= ~(1U << action);

	return 0;
}

bool xdp_program__chain_call_enabled(const struct xdp_program *prog,
				     enum xdp_action action)
{
	if (!prog || action >= XDP_DISPATCHER_RETVAL)
		return false;

	return !!(prog->chain_call_actions & (1U << action));
}

unsigned int xdp_program__run_prio(const struct xdp_program *prog)
{
	if (!prog)
		return XDP_DEFAULT_RUN_PRIO;

	return prog->run_prio;
}

int xdp_program__set_run_prio(struct xdp_program *prog, unsigned int run_prio)
{
	if (!prog || prog->prog_fd)
		return -EINVAL;

	prog->run_prio = run_prio;
	return 0;
}

const char *xdp_program__name(const struct xdp_program *prog)
{
	if (!prog)
		return NULL;

	return prog->prog_name;
}

struct bpf_object *xdp_program__bpf_obj(struct xdp_program *prog)
{
	if (!prog)
		return NULL;

	return prog->bpf_obj;
}


const unsigned char *xdp_program__tag(const struct xdp_program *prog)
{
	if (!prog)
		return NULL;

	return prog->prog_tag;
}

uint32_t xdp_program__id(const struct xdp_program *xdp_prog)
{
	if (!xdp_prog)
		return 0;

	return xdp_prog->prog_id;
}

int xdp_program__fd(const struct xdp_program *xdp_prog)
{
	if (!xdp_prog)
		return -1;

	return xdp_prog->prog_fd;
}

int xdp_program__print_chain_call_actions(const struct xdp_program *prog,
					  char *buf,
					  size_t buf_len)
{
	bool first = true;
	char *pos = buf;
	size_t len = 0;
	int i;

	if (!prog || !buf)
		return -EINVAL;

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

static bool get_field_int(const struct btf *btf,
			  const char *t_name,
			  const struct btf_type *t,
			  __u32 *res)
{
	const struct btf_array *arr_info;
	const struct btf_type *arr_t;

	if (!btf_is_ptr(t)) {
		pr_warn("attr '%s': expected PTR, got %u.\n",
			t_name, btf_kind(t));
		return false;
	}

	arr_t = btf__type_by_id(btf, t->type);
	if (!arr_t) {
		pr_warn("attr '%s': type [%u] not found.\n",
			t_name, t->type);
		return false;
	}
	if (!btf_is_array(arr_t)) {
		pr_warn("attr '%s': expected ARRAY, got %u.\n",
			t_name, btf_kind(arr_t));
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

/*
 * Find BTF func definition for func_name, which may be a truncated prefix of
 * the real function name.
 * Return NULL on no, or ambiguous, match.
 */
static const struct btf_type *btf_get_function(const struct btf *btf,
					       const char *func_name)
{
	const struct btf_type *t, *match;
	size_t len, matches = 0;
	const char *name;
	int nr_types, i;

	if (!btf) {
		pr_debug("No BTF found for program\n");
		return NULL;
	}

	len = strlen(func_name);

	nr_types = btf__get_nr_types(btf);
	for (i = 1; i <= nr_types; i++) {
		t = btf__type_by_id(btf, i);
		if (!btf_is_func(t))
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (!strncmp(name, func_name, len)) {
			pr_debug("Found func %s matching %s\n",
				 name, func_name);

			if (strlen(name) == len)
				return t; /* exact match */

			/* prefix, may not be unique */
			matches++;
			match = t;
		}
	}

	if (matches == 1) /* unique match */
		return match;

	pr_debug("Function '%s' not found or ambiguous (%zu matches).\n",
		 func_name, matches);
	return NULL;
}

static const struct btf_type *btf_get_datasec(const struct btf *btf,
					      const char *sec_name)
{
	const struct btf_type *t;
	int nr_types, i;
	const char *name;

	if (!btf) {
		pr_debug("No BTF found for program\n");
		return NULL;
	}

	nr_types = btf__get_nr_types(btf);
	for (i = 1; i <= nr_types; i++) {
		t = btf__type_by_id(btf, i);
		if (!btf_is_datasec(t))
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (strcmp(name, sec_name) == 0)
			return t;
	}

	pr_debug("DATASEC '%s' not found.\n", sec_name);
	return NULL;
}

static const struct btf_type *btf_get_section_var(const struct btf *btf,
						  const struct btf_type *sec,
						  const char *var_name,
						  __u16 kind)
{
	const struct btf_var_secinfo *vi;
	const struct btf_var *var_extra;
	const struct btf_type *var, *def;
	const char *name;
	int vlen, i;

	vlen = btf_vlen(sec);
	vi = btf_var_secinfos(sec);
	for (i = 0; i < vlen; i++, vi++) {
		var = btf__type_by_id(btf, vi->type);
		var_extra = btf_var(var);
		name = btf__name_by_offset(btf, var->name_off);

		if (strcmp(name, var_name))
			continue;

		if (!btf_is_var(var)) {
			pr_warn("struct '%s': unexpected var kind %u.\n",
				name, btf_kind(var));
			return ERR_PTR(-EINVAL);
		}
		if (var_extra->linkage != BTF_VAR_GLOBAL_ALLOCATED &&
		    var_extra->linkage != BTF_VAR_STATIC) {
			pr_warn("struct '%s': unsupported var linkage %u.\n",
				name, var_extra->linkage);
			return ERR_PTR(-EOPNOTSUPP);
		}

		def = skip_mods_and_typedefs(btf, var->type, NULL);
		if (btf_kind(def) != kind) {
			pr_warn("var '%s': unexpected def kind %u.\n",
				name, btf_kind(def));
			return ERR_PTR(-EINVAL);
		}
		return def;
	}
	return ERR_PTR(-ENOENT);
}

/**
 * This function parses the run config information attached to an XDP program.
 *
 * This information is specified using BTF, in a format similar to how
 * BTF-defined maps are done. The definition looks like this:
 *
 * struct {
 *	__uint(priority, 10);
 *	__uint(XDP_PASS, 1);
 * } XDP_RUN_CONFIG(FUNCNAME);
 *
 * The priority is simply an integer that will be used to sort programs as they
 * are attached on the interface (see cmp_xdp_programs() for full sort order).
 * In addition to the priority, the run config can define an integer value for
 * each XDP action. A non-zero value means that execution will continue to the
 * next loaded program if the current program returns that action. I.e., in the
 * above example, any return value other than XDP_PASS will cause the dispatcher
 * to exit with that return code, whereas XDP_PASS means execution will
 * continue.
 *
 * Since this information becomes part of the object file BTF info, it will
 * survive loading into the kernel, and so it can be retrieved for
 * already-loaded programs as well.
 */
static int xdp_program__parse_btf(struct xdp_program *xdp_prog)
{
	const struct btf *btf = xdp_program__btf(xdp_prog);
	const struct btf_type *def, *sec;
	const struct btf_member *m;
	char struct_name[100];
	int err, i, mlen;

	/* If the program name is the maximum allowed object name in the kernel,
	 * it may have been truncated, in which case we try to expand it by
	 * looking for a match in the BTF data.
	 */
	if (strlen(xdp_prog->prog_name) >= BPF_OBJ_NAME_LEN - 1) {
		const struct btf_type *func;
		char *name;

		func = btf_get_function(btf, xdp_prog->prog_name);
		if (func) {
			name = strdup(btf__name_by_offset(btf, func->name_off));
			if (!name)
				return -ENOMEM;
			free(xdp_prog->prog_name);
			xdp_prog->prog_name = name;
		}
	}

	err = try_snprintf(struct_name, sizeof(struct_name), "_%s",
			   xdp_program__name(xdp_prog));
	if (err)
		return err;

	sec = btf_get_datasec(btf, XDP_RUN_CONFIG_SEC);
	if (!sec)
		return -ENOENT;

	def = btf_get_section_var(btf, sec, struct_name, BTF_KIND_STRUCT);
	if (IS_ERR(def)) {
		pr_debug("Couldn't find run order struct %s\n", struct_name);
		return PTR_ERR(def);
	}

	mlen = btf_vlen(def);
	m = btf_members(def);
	for (i = 0; i < mlen; i++, m++) {
		const char *mname = btf__name_by_offset(btf, m->name_off);
		const struct btf_type *m_t;
		unsigned int val, act;

		if (!mname) {
			pr_warn("struct '%s': invalid field #%d.\n", struct_name, i);
			return -EINVAL;
		}
		m_t = skip_mods_and_typedefs(btf, m->type, NULL);

		if (!strcmp(mname, "priority")) {
			if (!get_field_int(btf, mname, m_t, &xdp_prog->run_prio))
				return -EINVAL;
			continue;
		} else if(get_xdp_action(mname, &act)) {
			if (!get_field_int(btf, mname, m_t, &val))
				return -EINVAL;
			xdp_program__set_chain_call_enabled(xdp_prog, act, val);
		} else {
			pr_warn("Invalid mname: %s\n", mname);
			return -ENOTSUP;
		}
	}
	return 0;

}

static struct xdp_program *xdp_program__new()
{
	struct xdp_program *xdp_prog;

	xdp_prog = malloc(sizeof(*xdp_prog));
	if (!xdp_prog)
		return ERR_PTR(-ENOMEM);

	memset(xdp_prog, 0, sizeof(*xdp_prog));

	xdp_prog->prog_fd = -1;
	xdp_prog->link_fd = -1;
	xdp_prog->run_prio = XDP_DEFAULT_RUN_PRIO;
	xdp_prog->chain_call_actions = XDP_DEFAULT_CHAIN_CALL_ACTIONS;

	return xdp_prog;
}

void xdp_program__close(struct xdp_program *xdp_prog)
{
	if (!xdp_prog)
		return;

	if (xdp_prog->link_fd >= 0)
		close(xdp_prog->link_fd);
	if (xdp_prog->prog_fd >= 0)
		close(xdp_prog->prog_fd);

	free(xdp_prog->prog_name);
	free(xdp_prog->attach_name);

	if (!xdp_prog->from_external_obj) {
		if (xdp_prog->bpf_obj)
			bpf_object__close(xdp_prog->bpf_obj);
		else if (xdp_prog->btf)
			btf__free(xdp_prog->btf);
	}

	free(xdp_prog);
}

static int xdp_program__fill_from_obj(struct xdp_program *xdp_prog,
				      struct bpf_object *obj,
				      const char *prog_name,
				      bool external)
{
	struct bpf_program *bpf_prog;
	int err;

	if (!xdp_prog || !obj)
		return -EINVAL;

	if (prog_name)
		bpf_prog = bpf_object__find_program_by_name(obj, prog_name);
	else
		bpf_prog = bpf_program__next(NULL, obj);

	if(!bpf_prog) {
		pr_warn("Couldn't find xdp program%s%s in bpf object\n",
			prog_name ? " with name " : "",
			prog_name ?: "");
		return -ENOENT;
	}

	xdp_prog->prog_name = strdup(bpf_program__name(bpf_prog));
	if (!xdp_prog->prog_name)
		return -ENOMEM;

	xdp_prog->bpf_prog = bpf_prog;
	xdp_prog->bpf_obj = obj;
	xdp_prog->btf = bpf_object__btf(obj);
	xdp_prog->from_external_obj = external;

	err = xdp_program__parse_btf(xdp_prog);
	if (err && err != -ENOENT)
		return err;

	return 0;
}

struct xdp_program *xdp_program__from_bpf_obj(struct bpf_object *obj,
					      const char *prog_name)
{
	struct xdp_program *xdp_prog;
	int err;

	if (!obj)
		return ERR_PTR(-EINVAL);

	xdp_prog = xdp_program__new();
	if (IS_ERR(xdp_prog))
		return xdp_prog;

	err = xdp_program__fill_from_obj(xdp_prog, obj, prog_name, true);
	if (err)
		goto err;

	return xdp_prog;
err:
	xdp_program__close(xdp_prog);
	return ERR_PTR(err);
}

struct xdp_program *xdp_program__open_file(const char *filename,
					   const char *prog_name,
					   struct bpf_object_open_opts *opts)
{
	struct xdp_program *xdp_prog;
	struct bpf_object *obj;
	int err;

	if (!filename)
		return ERR_PTR(-EINVAL);

	obj = bpf_object__open_file(filename, opts);
	err = libbpf_get_error(obj);
	if (err) {
		if (err == -ENOENT)
			pr_debug("Couldn't load the eBPF program (libbpf said 'no such file').\n"
				 "Maybe the program was compiled with a too old "
				 "version of LLVM (need v9.0+)?\n");
		return ERR_PTR(err);
	}

	xdp_prog = xdp_program__new();
	if (IS_ERR(xdp_prog)) {
		bpf_object__close(obj);
		return xdp_prog;
	}

	err = xdp_program__fill_from_obj(xdp_prog, obj, prog_name, false);
	if (err)
		goto err;

	return xdp_prog;
err:
	xdp_program__close(xdp_prog);
	bpf_object__close(obj);
	return ERR_PTR(err);
}

static bool try_bpf_file(char *buf, size_t buf_size,
			 char *path, const char *progname)
{
	struct stat sb = {};

	if (try_snprintf(buf, buf_size, "%s/%s", path, progname))
		return false;

	pr_debug("Looking for '%s'\n", buf);
	if (stat(buf, &sb))
		return false;

	return true;
}

static int find_bpf_file(char *buf, size_t buf_size, const char *progname)
{
	static char *bpf_obj_paths[] = {
#ifdef DEBUG
		".",
#endif
		BPF_OBJECT_PATH,
		NULL
	};
	char *path, **p;

	path = secure_getenv(XDP_OBJECT_ENVVAR);
	if (path && try_bpf_file(buf, buf_size, path, progname)) {
		return 0;
	} else if (!path) {
		for (p = bpf_obj_paths; *p; p++)
			if (try_bpf_file(buf, buf_size, *p, progname))
				return 0;
	}

	pr_warn("Couldn't find a BPF file with name %s\n", progname);
	return -ENOENT;
}

struct xdp_program *xdp_program__find_file(const char *filename,
					   const char *prog_name,
					   struct bpf_object_open_opts *opts)
{
	char buf[PATH_MAX];
	int err;

	err = find_bpf_file(buf, sizeof(buf), filename);
	if (err)
		return ERR_PTR(err);

	pr_debug("Loading XDP program '%s' from '%s'\n", prog_name, buf);
	return xdp_program__open_file(buf, prog_name, opts);
}

static int xdp_program__fill_from_fd(struct xdp_program *xdp_prog, int fd)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	struct btf *btf = NULL;
	int err = 0;

	if (!xdp_prog)
		return -EINVAL;

	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (err) {
		pr_warn("couldn't get program info: %s", strerror(errno));
		err = -errno;
		goto err;
	}

	if (!xdp_prog->prog_name) {
		xdp_prog->prog_name = strdup(info.name);
		if (!xdp_prog->prog_name) {
			err = -ENOMEM;
			pr_warn("failed to strdup program title");
			goto err;
		}
	}

	if (info.btf_id && !xdp_prog->btf) {
		err = btf__get_from_id(info.btf_id, &btf);
		if (err) {
			pr_warn("Couldn't get BTF for ID %ul\n", info.btf_id);
			goto err;
		}
		xdp_prog->btf = btf;
	}

	memcpy(xdp_prog->prog_tag, info.tag, BPF_TAG_SIZE);
	xdp_prog->load_time = info.load_time;
	xdp_prog->prog_fd = fd;
	xdp_prog->prog_id = info.id;

	return 0;
err:
	btf__free(btf);
	return err;
}

struct xdp_program *xdp_program__from_fd(int fd)
{
	struct xdp_program *xdp_prog = NULL;
	int err;

	xdp_prog = xdp_program__new();
	if (IS_ERR(xdp_prog))
		return xdp_prog;

	err = xdp_program__fill_from_fd(xdp_prog, fd);
	if (err)
		goto err;

	err = xdp_program__parse_btf(xdp_prog);
	if (err && err != -ENOENT)
		goto err;

	return xdp_prog;
err:
	free(xdp_prog);
	return ERR_PTR(err);
}

struct xdp_program *xdp_program__from_id(__u32 id)
{
	struct xdp_program *prog;
	int fd, err;

	fd = bpf_prog_get_fd_by_id(id);
	if (fd < 0) {
		err = -errno;
		pr_warn("couldn't get program fd: %s", strerror(-err));
		return ERR_PTR(err);
	}

	prog = xdp_program__from_fd(fd);
	if (IS_ERR(prog))
		close(fd);
	return prog;
}

struct xdp_program *xdp_program__from_pin(const char *pin_path)
{
	struct xdp_program *prog;
	int fd, err;

	fd = bpf_obj_get(pin_path);
	if (fd < 0) {
		err = -errno;
		pr_warn("couldn't get program fd from %s: %s",
			pin_path, strerror(-err));
		return ERR_PTR(err);
	}

	prog = xdp_program__from_fd(fd);
	if (IS_ERR(prog))
		close(fd);
	return prog;
}

static int cmp_xdp_programs(const void *_a, const void *_b)
{
	const struct xdp_program *a = *(struct xdp_program * const *)_a;
	const struct xdp_program *b = *(struct xdp_program * const *)_b;
	int cmp;

	if (a->run_prio != b->run_prio)
		return a->run_prio < b->run_prio ? -1 : 1;

	cmp = strcmp(a->prog_name, b->prog_name);
	if (cmp)
		return cmp;

	/* Hopefully the two checks above will resolve most comparisons; in
	 * cases where they don't, hopefully the checks below will keep the
	 * order stable.
	 */

	/* loaded before non-loaded */
	if (a->prog_fd >= 0 && b->prog_fd < 0)
		return -1;
	else if (a->prog_fd < 0 && b->prog_fd >= 0)
		return 1;

	/* two unloaded programs - compare by size */
	if (a->bpf_prog && b->bpf_prog) {
		size_t size_a, size_b;

		size_a = bpf_program__size(a->bpf_prog);
		size_b = bpf_program__size(b->bpf_prog);
		if (size_a != size_b)
			return size_a < size_b ? -1 : 1;
	}

	cmp = memcmp(a->prog_tag, b->prog_tag, BPF_TAG_SIZE);
	if (cmp)
		return cmp;

	/* at this point we are really grasping for straws */
	if (a->load_time != b->load_time)
		return a->load_time < b->load_time ? -1 : 1;

	return 0;
}

int xdp_program__pin(struct xdp_program *prog, const char *pin_path)
{
	if (!prog || !prog->prog_fd)
		return -EINVAL;

	return bpf_program__pin(prog->bpf_prog, pin_path);
}

static int xdp_program__load(struct xdp_program *prog)
{
	int err;

	if (!prog)
		return -EINVAL;

	if (prog->prog_fd >= 0)
		return -EEXIST;

	if (!prog->bpf_obj)
		return -EINVAL;

	err = bpf_object__load(prog->bpf_obj);
	if (err)
		return err;

	pr_debug("Loaded XDP program %s, got fd %d\n",
		 xdp_program__name(prog), bpf_program__fd(prog->bpf_prog));

	return xdp_program__fill_from_fd(prog, bpf_program__fd(prog->bpf_prog));
}

static struct xdp_program *xdp_program__clone(struct xdp_program *prog)
{
	struct xdp_program *new_prog;
	int new_fd, err;

	/* Clone a loaded program struct by duplicating the fd and creating a
	 * new structure from th ekernel state.
	 */
	if (!prog || !prog->prog_fd)
		return ERR_PTR(-EINVAL);

	new_fd = fcntl(prog->prog_fd, F_DUPFD_CLOEXEC);
	if (new_fd < 0) {
		err = -errno;
		pr_warn("Error on fcntl: %s\n", strerror(-err));
		return ERR_PTR(err);
	}

	new_prog = xdp_program__from_fd(new_fd);
	if (IS_ERR(new_prog))
		close(new_fd);
	return new_prog;
}

int xdp_program__attach_multi(struct xdp_program **progs, size_t num_progs,
			      int ifindex, enum xdp_attach_mode mode)
{
	struct xdp_multiprog *old_mp, *mp;
	int err = 0;

	if (!progs || !num_progs)
		return -EINVAL;

	old_mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (!IS_ERR_OR_NULL(old_mp)) {
		pr_warn("XDP program already loaded on ifindex %d; "
			"replacing not yet supported", ifindex);
		xdp_multiprog__close(old_mp);
		return -EEXIST;
	}

	mp = xdp_multiprog__generate(progs, num_progs);
	if (IS_ERR(mp)) {
		err = PTR_ERR(mp);
		mp = NULL;
		goto out;
	}

	err = xdp_multiprog__pin(mp);
	if (err) {
		pr_warn("Failed to pin program: %s\n", strerror(-err));
		goto out_close;
	}

	err = xdp_multiprog__attach(NULL, mp, ifindex, mode);
	if (err) {
		pr_warn("Failed to attach dispatcher on ifindex %d: %s\n",
			ifindex, strerror(-err));
		xdp_multiprog__unpin(mp);
		goto out_close;
	}

out_close:
	xdp_multiprog__close(mp);
out:
	return err;
}

int xdp_program__attach(struct xdp_program *prog, int ifindex,
			enum xdp_attach_mode mode)
{
	if (!prog || IS_ERR(prog))
		return -EINVAL;

	return xdp_program__attach_multi(&prog, 1, ifindex, mode);
}


int xdp_program__detach_multi(struct xdp_program **progs, size_t num_progs,
			      int ifindex, enum xdp_attach_mode mode)
{
	struct xdp_multiprog *mp;
	int err = 0, i;

	mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (IS_ERR_OR_NULL(mp) || mp->is_legacy) {
		pr_warn("No XDP dispatcher found on ifindex %d\n", ifindex);
		return -ENOENT;
	}

	if (mode != XDP_MODE_UNSPEC && mp->attach_mode != mode) {
		pr_warn("XDP dispatcher attached in mode %d, requested %d\n",
			mp->attach_mode, mode);
		err = -ENOENT;
		goto out;
	}

	/* fist pass - check progs and count number still loaded */
	for (i = 0; i < num_progs; i++) {
		struct xdp_program *p = NULL;
		bool found = false;

		if (!progs[i]->prog_id) {
			pr_warn("Program %d not loaded\n", i);
			err = -EINVAL;
			goto out;
		}

		while ((p = xdp_multiprog__next_prog(p, mp))) {
			if (progs[i]->prog_id == p->prog_id)
				found = true;
		}

		if (!found) {
			pr_warn("Couldn't find program with id %d on ifindex %d\n",
				progs[i]->prog_id, ifindex);
			err = -ENOENT;
			goto out;
		}
	}

	if (num_progs == mp->num_links) {
		err = xdp_multiprog__detach(mp, ifindex);
		if (err)
			goto out;
	} else {
		pr_warn("Asked to detach %zu progs, but %zu loaded on ifindex %d; "
			"partial detach not yet supported.\n",
			num_progs, mp->num_links, ifindex);
		err = -EINVAL;
		goto out;
	}

out:
	xdp_multiprog__close(mp);
	return err;
}

int xdp_program__detach(struct xdp_program *prog, int ifindex,
			enum xdp_attach_mode mode)
{
	if (!prog || IS_ERR(prog))
		return -EINVAL;

	return xdp_program__detach_multi(&prog, 1, ifindex, mode);
}


void xdp_multiprog__close(struct xdp_multiprog *mp)
{
	struct xdp_program *p, *next = NULL;

	if (!mp)
		return;

	xdp_program__close(mp->main_prog);
	for (p = mp->first_prog; p; p = next) {
		next = p->next;
		xdp_program__close(p);
	}

	free(mp);
}

static int xdp_multiprog__main_fd(struct xdp_multiprog *mp)
{
	if (!mp)
		return -EINVAL;

	if (!mp->main_prog)
		return -ENOENT;

	return mp->main_prog->prog_fd;
}

static struct xdp_multiprog *xdp_multiprog__new()
{
	struct xdp_multiprog *mp;

	mp = malloc(sizeof *mp);
	if (!mp)
		return ERR_PTR(-ENOMEM);
	memset(mp, 0, sizeof(*mp));

	return mp;
}

static int xdp_multiprog__load(struct xdp_multiprog *mp)
{
	int err = 0;

	if (!mp || !mp->main_prog || mp->is_loaded || mp->is_legacy)
		return -EINVAL;

	pr_debug("Loading multiprog dispatcher for %d programs\n",
		mp->config.num_progs_enabled);

	err = xdp_program__load(mp->main_prog);
	if (err) {
		pr_warn("Failed to load dispatcher: %s\n", strerror(-err));
		goto out;
	}
	mp->is_loaded = true;
out:
	return err;
}

static int check_dispatcher_version(struct btf *btf)
{
	const char *name = "dispatcher_version";
	const struct btf_type *sec, *def;
	__u32 version;

	sec = btf_get_datasec(btf, XDP_METADATA_SECTION);
	if (!sec)
		return -ENOENT;

	def = btf_get_section_var(btf, sec, name, BTF_KIND_PTR);
	if (IS_ERR(def))
		return PTR_ERR(def);

	if (!get_field_int(btf, name, def, &version))
		return -ENOENT;

	if (version > XDP_DISPATCHER_VERSION) {
		pr_warn("XDP dispatcher version %d higher than supported %d\n",
			version, XDP_DISPATCHER_VERSION);
		return -EOPNOTSUPP;
	}
	pr_debug("Verified XDP dispatcher version %d <= %d\n",
		 version, XDP_DISPATCHER_VERSION);
	return 0;
}

static int xdp_multiprog__link_pinned_progs(struct xdp_multiprog *mp)
{
	struct xdp_program *prog, *p = mp->first_prog;
	char buf[PATH_MAX], pin_path[PATH_MAX];
	const char *bpffs_dir;
	int err, lock_fd, i;
	struct stat sb = {};

	if (!mp)
		return -EINVAL;

	bpffs_dir = get_bpffs_dir();
	if (IS_ERR(bpffs_dir))
		return PTR_ERR(bpffs_dir);

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/dispatch-%d",
			   bpffs_dir, mp->main_prog->prog_id);
	if (err)
		return err;

	lock_fd = xdp_lock_acquire();
	if (lock_fd < 0)
		return lock_fd;

	pr_debug("Reading multiprog component programs from pinned directory\n");
	err = stat(pin_path, &sb);
	if (err) {
		err = -errno;
		pr_debug("Couldn't stat pin_path '%s': %s\n",
			 pin_path, strerror(-err));
		goto out;
	}

	for (i = 0; i < mp->config.num_progs_enabled; i++) {

		err = try_snprintf(buf, sizeof(buf), "%s/prog%d-prog",
				   pin_path, i);
		if (err)
			goto err;

		prog = xdp_program__from_pin(buf);
		if (IS_ERR(prog)) {
			err = PTR_ERR(prog);
			goto err;
		}
		err = try_snprintf(buf, sizeof(buf), "prog%d", i);
		if (err)
			goto err;
		prog->attach_name = strdup(buf);
		if (!prog->attach_name) {
			err = -ENOMEM;
			goto err;
		}

		prog->chain_call_actions = (mp->config.chain_call_actions[i]
					    & ~(1U << XDP_DISPATCHER_RETVAL));
		prog->run_prio = mp->config.run_prios[i];

		if (!p) {
			mp->first_prog = prog;
			p = mp->first_prog;
		} else {
			p->next = prog;
			p = prog;
		}
		mp->num_links++;
	}

out:
	xdp_lock_release(lock_fd);
	return err;
err:
	prog = mp->first_prog;
	while (prog) {
		p = prog->next;
		xdp_program__close(prog);
		prog = p;
	}
	mp->first_prog = NULL;
	goto out;
}

static int xdp_multiprog__fill_from_fd(struct xdp_multiprog *mp, int prog_fd)
{
	__u32 *map_id, map_key = 0, map_info_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info_linear *info_linear;
	struct bpf_map_info map_info = {};
	struct bpf_prog_info *info;
	struct xdp_program *prog;
	struct btf *btf = NULL;
	__u64 arrays;
	int err = 0;
	int map_fd;

	if (!mp)
		return -EINVAL;

	arrays = (1UL << BPF_PROG_INFO_MAP_IDS);
	info_linear = bpf_program__get_prog_info_linear(prog_fd, arrays);
	if (IS_ERR_OR_NULL(info_linear)) {
		pr_warn("couldn't get program info for fd: %d", prog_fd);
		return -EINVAL;
	}

	info = &info_linear->info;
	if (!info->btf_id) {
		pr_warn("No BTF for prog ID %u\n", info->id);
		err = -ENOENT;
		goto out;
	}

	err = btf__get_from_id(info->btf_id, &btf);
	if (err) {
		pr_warn("Couldn't get BTF for ID %ul\n", info->btf_id);
		goto out;
	}

	err = check_dispatcher_version(btf);
	if (err) {
		if (err != -ENOENT) {
			pr_warn("Dispatcher version check failed for ID %d\n",
				info->id);
			goto out;
		} else {
			/* no dispatcher, mark as legacy prog */
			mp->is_legacy = true;
			err = 0;
			goto legacy;
		}
	}

	if (info->nr_map_ids != 1) {
		pr_warn("Expected a single map for dispatcher, found %d\n",
			info->nr_map_ids);
		err = -EINVAL;
		goto out;
	}
	map_id = (void *)info_linear->data;

	map_fd = bpf_map_get_fd_by_id(*map_id);
	if (map_fd < 0) {
		err = map_fd;
		pr_warn("Could not get config map fd: %s\n", strerror(-err));
		goto out;
	}
	err = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len);
	if (err) {
		pr_warn("Couldn't get map info: %s\n", strerror(-err));
		goto out;
	}

	if (map_info.key_size != sizeof(map_key) ||
	    map_info.value_size != sizeof(mp->config)) {
		pr_warn("Map key or value size mismatch\n");
		err = -EINVAL;
		goto out;
	}

	err = bpf_map_lookup_elem(map_fd, &map_key, &mp->config);
	if (err) {
		pr_warn("Could not lookup map value: %s\n", strerror(-err));
		goto out;
	}

legacy:
	prog = xdp_program__from_fd(prog_fd);
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		goto out;
	}
	mp->main_prog = prog;

	if (!mp->is_legacy) {
		err = xdp_multiprog__link_pinned_progs(mp);
		if (err)
			goto err;
	}

	mp->is_loaded = true;
	pr_debug("Found %s with id %d and %zu component progs\n",
		 mp->is_legacy ? "legacy program" : "multiprog",
		 mp->main_prog->prog_id, mp->num_links);

out:
	free(info_linear);
	return err;

err:
	xdp_program__close(prog);
	goto out;
}

static struct xdp_multiprog *xdp_multiprog__from_fd(int fd)
{
	struct xdp_multiprog *mp = NULL;
	int err;

	mp = xdp_multiprog__new();
	if (IS_ERR(mp))
		return mp;

	err = xdp_multiprog__fill_from_fd(mp, fd);
	if (err)
		goto err;

	return mp;
err:
	free(mp);
	return ERR_PTR(err);
}


static struct xdp_multiprog *xdp_multiprog__from_id(__u32 id)
{
	struct xdp_multiprog *mp;
	int fd, err;

	fd = bpf_prog_get_fd_by_id(id);
	if (fd < 0) {
		err = -errno;
		pr_warn("couldn't get program fd: %s", strerror(-err));
		return ERR_PTR(err);
	}
	mp = xdp_multiprog__from_fd(fd);
	if (IS_ERR_OR_NULL(mp))
		close(fd);
	return mp;
}

struct xdp_multiprog *xdp_multiprog__get_from_ifindex(int ifindex)
{
	struct xdp_link_info xinfo = {};
	enum xdp_attach_mode mode;
	struct xdp_multiprog *mp;
	__u32 prog_id = 0;
	int err;

	err = bpf_get_link_xdp_info(ifindex, &xinfo, sizeof(xinfo), 0);
	if (err)
		return ERR_PTR(err);

	if (xinfo.attach_mode == XDP_ATTACHED_SKB) {
		prog_id = xinfo.skb_prog_id;
		mode = XDP_MODE_SKB;
	} else {
		prog_id = xinfo.drv_prog_id;
		mode = XDP_MODE_NATIVE;
	}

	if (!prog_id)
		return ERR_PTR(-ENOENT);

	mp = xdp_multiprog__from_id(prog_id);
	if (!IS_ERR_OR_NULL(mp))
		mp->attach_mode = mode;
	return mp;
}

static int xdp_multiprog__link_prog(struct xdp_multiprog *mp,
				    struct xdp_program *prog)
{
	struct xdp_program *new_prog, *p;
	char buf[PATH_MAX];
	int err, lfd;

	if (!mp || !prog || !mp->is_loaded ||
	    mp->num_links >= mp->config.num_progs_enabled)
		return -EINVAL;

	pr_debug("Linking prog %s as multiprog entry %zu\n",
		 xdp_program__name(prog), mp->num_links);

	err = try_snprintf(buf, sizeof(buf), "prog%d", mp->num_links);
	if (err)
		goto err;

	if (prog->prog_fd >= 0) {
		/* FIXME: We want to be able to re-attach already-loaded
		 * programs into a new dispatcher here; but the kernel doesn't
		 * currently allow this.
		 */
		return -EOPNOTSUPP;
	} else {
		err = bpf_program__set_attach_target(prog->bpf_prog,
						     mp->main_prog->prog_fd,
						     buf);
		if (err) {
			pr_debug("Failed to set attach target: %s\n", strerror(-err));
			goto err;
		}

		bpf_program__set_type(prog->bpf_prog, BPF_PROG_TYPE_EXT);
		err = xdp_program__load(prog);
		if (err) {
			pr_warn("Failed to load program %s: %s\n",
				xdp_program__name(prog), strerror(-err));
			goto err;
		}

		/* clone the xdp_program ref so we can keep it */
		new_prog = xdp_program__clone(prog);
		if (IS_ERR(new_prog)) {
			err = PTR_ERR(new_prog);
			pr_warn("Failed to clone xdp_program: %s\n",
				strerror(-err));
			goto err;
		}

		/* The attach will disappear once this fd is closed */
		lfd = bpf_raw_tracepoint_open(NULL, new_prog->prog_fd);
		if (lfd < 0) {
			err = lfd;
			pr_warn("Failed to attach program %s to dispatcher: %s\n",
				xdp_program__name(new_prog), strerror(-err));
			goto err_free;
		}

		new_prog->attach_name = strdup(buf);
		if (!new_prog->attach_name) {
			err = -ENOMEM;
			goto err_free;
		}

		pr_debug("Attached prog '%s' with priority %d in dispatcher entry '%s' with fd %d\n",
			 xdp_program__name(new_prog), xdp_program__run_prio(new_prog),
			 new_prog->attach_name, lfd);
		new_prog->link_fd = lfd;

		if (!mp->first_prog) {
			mp->first_prog = new_prog;
		} else {
			p = mp->first_prog;
			while (p->next)
				p = p->next;
			p->next = new_prog;
		}
	}

	mp->num_links++;
	return 0;

err_free:
	xdp_program__close(new_prog);
err:
	return err;
}

static struct xdp_multiprog *
xdp_multiprog__generate(struct xdp_program **progs,
			size_t num_progs)
{
	struct xdp_program *dispatcher;
	struct xdp_multiprog *mp;
	struct bpf_map *map;
	char buf[PATH_MAX];
	int err, i;

	if (!progs || !num_progs || num_progs > MAX_DISPATCHER_ACTIONS)
		return ERR_PTR(-EINVAL);

	pr_debug("Generating multi-prog dispatcher for %zu programs\n", num_progs);

	if (num_progs > 1)
		qsort(progs, num_progs, sizeof(*progs), cmp_xdp_programs);

	mp = xdp_multiprog__new(num_progs);
	if (IS_ERR(mp))
		return mp;

	dispatcher = xdp_program__find_file("xdp-dispatcher.o",
					    "xdp_dispatcher", NULL);
	if (IS_ERR(dispatcher)) {
		err = PTR_ERR(dispatcher);
		pr_warn("Couldn't open BPF file %s\n", buf);
		goto err;
	}

	err = check_dispatcher_version(dispatcher->btf);
	if (err) {
		pr_warn("XDP dispatcher object version check failed\n");
		goto err;
	}

	mp->main_prog = dispatcher;

	map = bpf_map__next(NULL, mp->main_prog->bpf_obj);
	if (!map) {
		pr_warn("Couldn't find rodata map in object file %s\n", buf);
		err = -ENOENT;
		goto err;
	}

	mp->config.num_progs_enabled = num_progs;
	for (i = 0; i < num_progs; i++) {
		mp->config.chain_call_actions[i] = (progs[i]->chain_call_actions |
						    (1U << XDP_DISPATCHER_RETVAL));
		mp->config.run_prios[i] = progs[i]->run_prio;
	}

	err = bpf_map__set_initial_value(map, &mp->config, sizeof(mp->config));
	if (err) {
		pr_warn("Failed to set rodata for object file %s\n", buf);
		goto err;
	}

	err = xdp_multiprog__load(mp);
	if (err)
		goto err;

	for (i = 0; i < num_progs; i++) {
		err = xdp_multiprog__link_prog(mp, progs[i]);
		if (err)
			goto err;
	}

	return mp;

err:
	xdp_multiprog__close(mp);
	return ERR_PTR(err);
}

static int xdp_multiprog__pin(struct xdp_multiprog *mp)
{
	char pin_path[PATH_MAX], buf[PATH_MAX];
	struct xdp_program *prog;
	const char *bpffs_dir;
	int err = 0, lock_fd;

	if (!mp || mp->is_legacy)
		return -EINVAL;

	bpffs_dir = get_bpffs_dir();
	if (IS_ERR(bpffs_dir))
		return PTR_ERR(bpffs_dir);

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/dispatch-%d",
			   bpffs_dir, mp->main_prog->prog_id);
	if (err)
		return err;

	lock_fd = xdp_lock_acquire();
	if (lock_fd < 0)
		return lock_fd;

	pr_debug("Pinning multiprog fd %d beneath %s\n",
		 mp->main_prog->prog_fd, pin_path);

	err = mkdir(pin_path, S_IRWXU);
	if (err && errno != EEXIST) {
		err = -errno;
		goto out;
	}

	for (prog = mp->first_prog; prog; prog = prog->next) {
		if (prog->link_fd < 0) {
			err = -EINVAL;
			pr_warn("Prog %s not linked\n", xdp_program__name(prog));
			goto err_unpin;
		}

		err = try_snprintf(buf, sizeof(buf), "%s/%s-link",
				   pin_path, prog->attach_name);
		if (err)
			goto err_unpin;

		err = bpf_obj_pin(prog->link_fd, buf);
		if (err) {
			pr_warn("Couldn't pin link FD at %s: %s\n", buf, strerror(-err));
			goto err_unpin;
		}
		pr_debug("Pinned link for prog %s at %s\n",
			 xdp_program__name(prog), buf);

		err = try_snprintf(buf, sizeof(buf), "%s/%s-prog",
				   pin_path, prog->attach_name);
		if (err)
			goto err_unpin;

		err = bpf_obj_pin(prog->prog_fd, buf);
		if (err) {
			pr_warn("Couldn't pin prog FD at %s: %s\n", buf, strerror(-err));
			goto err_unpin;
		}

		pr_debug("Pinned prog %s at %s\n", xdp_program__name(prog), buf);
	}
out:
	xdp_lock_release(lock_fd);
	return err;

err_unpin:
	for (prog = mp->first_prog; prog; prog = prog->next) {
		if (!try_snprintf(buf, sizeof(buf), "%s/%s-link",
				  pin_path, prog->attach_name))
			unlink(buf);
		if (!try_snprintf(buf, sizeof(buf), "%s/%s-prog",
				  pin_path, prog->attach_name))
			unlink(buf);
	}
	rmdir(pin_path);
	goto out;
}

static int xdp_multiprog__unpin(struct xdp_multiprog *mp)
{
	char pin_path[PATH_MAX], buf[PATH_MAX];
	struct xdp_program *prog;
	const char *bpffs_dir;
	int err = 0, lock_fd;

	if (!mp || mp->is_legacy)
		return -EINVAL;

	bpffs_dir = get_bpffs_dir();
	if (IS_ERR(bpffs_dir))
		return PTR_ERR(bpffs_dir);

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/dispatch-%d",
			   bpffs_dir, mp->main_prog->prog_id);
	if (err)
		return err;

	lock_fd = xdp_lock_acquire();
	if (lock_fd < 0)
		return lock_fd;

	pr_debug("Unpinning multiprog fd %d beneath %s\n",
		 mp->main_prog->prog_fd, pin_path);

	for (prog = mp->first_prog; prog; prog = prog->next) {
		err = try_snprintf(buf, sizeof(buf), "%s/%s-link",
				   pin_path, prog->attach_name);
		if (err)
			goto out;

		err = unlink(buf);
		if (err) {
			err = -errno;
			pr_warn("Couldn't unlink file %s: %s\n",
				buf, strerror(-err));
			goto out;
		}
		pr_debug("Unpinned link for prog %s from %s\n",
			 xdp_program__name(prog), buf);

		err = try_snprintf(buf, sizeof(buf), "%s/%s-prog",
				   pin_path, prog->attach_name);
		if (err)
			goto out;

		err = unlink(buf);
		if (err) {
			err = -errno;
			pr_warn("Couldn't unlink file %s: %s\n",
				buf, strerror(-err));
			goto out;
		}

		pr_debug("Unpinned prog %s from %s\n",
			 xdp_program__name(prog), buf);
	}

	err = rmdir(pin_path);
	if (err)
		err = -errno;
	pr_debug("Removed pin directory %s\n", pin_path);
out:
	xdp_lock_release(lock_fd);
	return err;
}

static int xdp_multiprog__attach(struct xdp_multiprog *old_mp,
				 struct xdp_multiprog *mp,
				 int ifindex, enum xdp_attach_mode mode)
{
	int err = 0, xdp_flags = 0, prog_fd = -1;
	DECLARE_LIBBPF_OPTS(bpf_xdp_set_link_opts, opts,
		.old_fd = -1);

	if (!mp && !old_mp)
		return -EINVAL;

	if (mp) {
		prog_fd = xdp_multiprog__main_fd(mp);
		if (prog_fd < 0)
			return -EINVAL;
	}

	if (old_mp) {
		opts.old_fd = xdp_multiprog__main_fd(old_mp);
		if (opts.old_fd < 0)
			return -EINVAL;
	} else {
		xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	}

	pr_debug("Replacing XDP fd %d with %d on ifindex %d\n",
		 opts.old_fd, prog_fd, ifindex);

	switch (mode) {
	case XDP_MODE_SKB:
		xdp_flags |= XDP_FLAGS_SKB_MODE;
		break;
	case XDP_MODE_NATIVE:
		xdp_flags |= XDP_FLAGS_DRV_MODE;
		break;
	case XDP_MODE_HW:
		xdp_flags |= XDP_FLAGS_HW_MODE;
		break;
	case XDP_MODE_UNSPEC:
		break;
	}

	err = bpf_set_link_xdp_fd_opts(ifindex, prog_fd, xdp_flags, &opts);
	if (err < 0) {
		pr_warn("Error attaching XDP program to ifindex %d: %s\n",
			ifindex, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			pr_debug("XDP already loaded on device\n");
			break;
		case EOPNOTSUPP:
			pr_debug("XDP mode not supported; try using SKB mode\n");
			break;
		default:
			break;
		}
		goto err;
	}

	if (mp)
		pr_debug("Loaded %zu programs on ifindex '%d'%s\n",
			 mp->num_links, ifindex,
			 mode == XDP_MODE_SKB ? " in skb mode" : "");
	else
		pr_debug("Detached multiprog on ifindex '%d'%s\n",
			 ifindex, mode == XDP_MODE_SKB ? " in skb mode" : "");

	return 0;
err:
	return err;
}

int xdp_multiprog__detach(struct xdp_multiprog *mp, int ifindex)
{
	int err;

	if (!mp || !mp->is_loaded)
		return -EINVAL;

	err = xdp_multiprog__attach(mp, NULL, ifindex, mp->attach_mode);
	if (err)
		return err;

	return xdp_multiprog__unpin(mp);
}


struct xdp_program *xdp_multiprog__next_prog(const struct xdp_program *prog,
					     const struct xdp_multiprog *mp)
{
	if (!mp || mp->is_legacy)
		return NULL;

	if (prog)
		return prog->next;

	return mp->first_prog;
}

enum xdp_attach_mode xdp_multiprog__attach_mode(const struct xdp_multiprog *mp)
{
	if (!mp)
		return XDP_MODE_UNSPEC;

	return mp->attach_mode;
}

struct xdp_program *xdp_multiprog__main_prog(const struct xdp_multiprog *mp)
{
	if (!mp)
		return NULL;

	return mp->main_prog;
}

bool xdp_multiprog__is_legacy(const struct xdp_multiprog *mp)
{
	return !!(mp && mp->is_legacy);
}
