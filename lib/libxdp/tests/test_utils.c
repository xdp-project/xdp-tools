/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include "test_utils.h"
#include <linux/err.h> /* ERR_PTR */

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

static bool try_bpf_file(char *buf, size_t buf_size, char *path,
			 const char *progname)
{
	struct stat sb = {};

	if (try_snprintf(buf, buf_size, "%s/%s", path, progname))
		return false;

	if (stat(buf, &sb))
		return false;

	return true;
}

int find_bpf_file(char *buf, size_t buf_size, const char *progname)
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

	fprintf(stderr, "Couldn't find a BPF file with name %s\n", progname);
	return -ENOENT;
}

struct bpf_object *open_bpf_file(const char *progname,
				 struct bpf_object_open_opts *opts)
{
	char buf[PATH_MAX];
	int err;

	err = find_bpf_file(buf, sizeof(buf), progname);
	if (err)
		return ERR_PTR(err);

	return bpf_object__open_file(buf, opts);
}
