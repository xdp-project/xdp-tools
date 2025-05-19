/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <linux/if_link.h> /* Need XDP flags */
#include <linux/magic.h> /* BPF FS magic */
#include <linux/err.h> /* ERR_PTR */
#include <bpf/bpf.h>
#include <dirent.h>
#include <net/if.h>

#include "util.h"
#include "logging.h"

static struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {"unspecified", XDP_MODE_UNSPEC},
       {NULL, 0}
};

int try_snprintf(char *buf, size_t buf_len, const char *format, ...)
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

static int set_rlimit(unsigned int min_limit)
{
	struct rlimit limit;
	int err = 0;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't get current rlimit\n");
		return err;
	}

	if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur == 0) {
		pr_debug("Current rlimit is infinity or 0. Not raising\n");
		return -ENOMEM;
	}

	if (min_limit) {
		if (limit.rlim_cur >= min_limit) {
			pr_debug("Current rlimit %ju already >= minimum %u\n",
				 (uintmax_t)limit.rlim_cur, min_limit);
			return 0;
		}
		pr_debug("Setting rlimit to minimum %u\n", min_limit);
		limit.rlim_cur = min_limit;
	} else {
		pr_debug("Doubling current rlimit of %ju\n", (uintmax_t)limit.rlim_cur);
		limit.rlim_cur <<= 1;
	}
	limit.rlim_max = max(limit.rlim_cur, limit.rlim_max);

	err = setrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't raise rlimit: %s\n", strerror(-err));
		return err;
	}

	return 0;
}

int double_rlimit(void)
{
	pr_debug("Permission denied when loading eBPF object; "
		 "raising rlimit and retrying\n");

	return set_rlimit(0);
}

static const char *_libbpf_compile_version = LIBBPF_VERSION;
static char _libbpf_version[10] = {};

const char *get_libbpf_version(void)
{
	/* Start by copying compile-time version into buffer so we have a
	 * fallback value in case we are dynamically linked, or can't find a
	 * version in /proc/self/maps below.
	 */
	strncpy(_libbpf_version, _libbpf_compile_version,
		sizeof(_libbpf_version)-1);

#ifdef LIBBPF_DYNAMIC
	char path[PATH_MAX], buf[PATH_MAX], *s;
	bool found = false;
	FILE *fp;

	/* When dynamically linking against libbpf, we can't be sure that the
	 * version we discovered at compile time is actually the one we are
	 * using at runtime. This can lead to hard-to-debug errors, so we try to
	 * discover the correct version at runtime.
	 *
	 * The simple solution to this would be if libbpf itself exported a
	 * version in its API. But since it doesn't, we work around this by
	 * parsing the mappings of the binary at runtime, looking for the full
	 * filename of libbpf.so and using that.
	 */
	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		goto out;

	while ((s = fgets(buf, sizeof(buf), fp)) != NULL) {
		/* We are looking for a line like:
		 * 7f63c2105000-7f63c2106000 rw-p 00032000 fe:02 4200947                    /usr/lib/libbpf.so.0.1.0
		 */
		if (sscanf(s, "%*x-%*x %*4c %*x %*5c %*d %s\n", path) == 1 &&
		    (s = strstr(path, "libbpf.so.")) != NULL) {
			strncpy(_libbpf_version, s+10, sizeof(_libbpf_version)-1);
			found = true;
			break;
		}
	}

	fclose(fp);
out:
	if (!found)
		pr_warn("Couldn't find runtime libbpf version - falling back to compile-time value!\n");

#endif
	_libbpf_version[sizeof(_libbpf_version)-1] = '\0';
	return _libbpf_version;
}

static bool try_bpf_file(char *buf, size_t buf_size, char *path,
			 const char *progname)
{
	struct stat sb = {};

	if (try_snprintf(buf, buf_size, "%s/%s", path, progname))
		return false;

	pr_debug("Looking for '%s'\n", buf);
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

	pr_warn("Couldn't find a BPF file with name %s\n", progname);
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

	pr_debug("Loading bpf file '%s' from '%s'\n", progname, buf);
	return bpf_object__open_file(buf, opts);
}

static int get_pinned_object_fd(const char *path, void *info, __u32 *info_len)
{
	char errmsg[STRERR_BUFSIZE];
	int pin_fd, err;

	pin_fd = bpf_obj_get(path);
	if (pin_fd < 0) {
		err = -errno;
		libbpf_strerror(-err, errmsg, sizeof(errmsg));
		pr_debug("Couldn't retrieve pinned object '%s': %s\n", path, errmsg);
		return err;
	}

	if (info) {
		err = bpf_obj_get_info_by_fd(pin_fd, info, info_len);
		if (err) {
			err = -errno;
			libbpf_strerror(-err, errmsg, sizeof(errmsg));
			pr_debug("Couldn't retrieve object info: %s\n", errmsg);
			return err;
		}
	}

	return pin_fd;
}

int make_dir_subdir(const char *parent, const char *dir)
{
	char path[PATH_MAX];
	int err;

	err = try_snprintf(path, sizeof(path), "%s/%s", parent, dir);
	if (err)
		return err;

	err = mkdir(parent, S_IRWXU);
	if (err && errno != EEXIST) {
		err = -errno;
		return err;
	}

	err = mkdir(path, S_IRWXU);
	if (err && errno != EEXIST) {
		err = -errno;
		return err;
	}

	return 0;
}

int attach_xdp_program(struct xdp_program *prog, const struct iface *iface,
		       enum xdp_attach_mode mode, const char *pin_root_path)
{
	char pin_path[PATH_MAX];
	int err = 0;

	if (!prog || !pin_root_path)
		return -EINVAL;

	err = make_dir_subdir(pin_root_path, "programs");
	if (err) {
		pr_warn("Unable to create pin directory: %s\n", strerror(-err));
		return err;
	}

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s/%s",
			   pin_root_path, iface->ifname,
			   xdp_program__name(prog));
	if (err)
		return err;

	err = xdp_program__attach(prog, iface->ifindex, mode, 0);
	if (err) {
		if (pin_root_path && err != -EEXIST)
			unlink(pin_path);
		return err;
	}

	pr_debug("Program '%s' loaded on interface '%s'%s\n",
		 xdp_program__name(prog), iface->ifname,
		 mode == XDP_MODE_SKB ? " in skb mode" : "");

	err = xdp_program__pin(prog, pin_path);
	if (err) {
		pr_warn("Unable to pin XDP program at %s: %s\n",
			pin_path, strerror(-err));
		goto unload;
	}
	pr_debug("XDP program pinned at %s\n", pin_path);
	return err;

unload:
	xdp_program__detach(prog, iface->ifindex, mode, 0);
	return err;
}

int detach_xdp_program(struct xdp_program *prog, const struct iface *iface,
		       enum xdp_attach_mode mode, const char *pin_root_path)
{
	char pin_path[PATH_MAX];
	int err;

	err = xdp_program__detach(prog, iface->ifindex, mode, 0);
	if (err)
		goto out;

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s/%s",
			   pin_root_path, iface->ifname,
			   xdp_program__name(prog));
	if (err)
		return err;

	err = unlink(pin_path);
	if (err && errno != ENOENT)
		goto out;

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
			   pin_root_path, iface->ifname);
	if (err)
		goto out;

	err = rmdir(pin_path);
	if (err && errno == ENOENT)
		err = 0;
	else if (err)
		err = -errno;
out:
	return err;
}

int get_pinned_program(const struct iface *iface, const char *pin_root_path,
		       enum xdp_attach_mode *mode,
		       struct xdp_program **xdp_prog)
{
	int ret = -ENOENT, err, ifindex = iface->ifindex;
	char pin_path[PATH_MAX];
	bool remove_all = false;
	enum xdp_attach_mode m;
	struct dirent *de;
	DIR *dr;

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
			   pin_root_path, iface->ifname);
	if (err)
		return err;

	dr = opendir(pin_path);
	if (!dr) {
		err = -errno;
		pr_debug("Couldn't open pin directory %s: %s\n",
			 pin_path, strerror(-err));
		return err;
	}

	if (!ifindex)
		ifindex = if_nametoindex(iface->ifname);
	if (!ifindex) {
		pr_debug("Interface %s no longer exists\n", iface->ifname);
		remove_all = true;
		ret = -ENODEV;
	}

	while ((de = readdir(dr)) != NULL) {
		DECLARE_LIBXDP_OPTS(xdp_program_opts, opts, 0);
		struct xdp_program *prog;

		if (!strcmp(".", de->d_name) || !strcmp("..", de->d_name))
			continue;

		err = try_snprintf(pin_path, sizeof(pin_path),
				   "%s/programs/%s/%s", pin_root_path,
				   iface->ifname, de->d_name);
		if (err)
			goto out;

		if (remove_all) {
			err = unlink(pin_path);
			if (err)
				ret = err;
			continue;
		}

		opts.pin_path = pin_path;
		prog = xdp_program__create(&opts);
		if (libxdp_get_error(prog) ||
		    !(m = xdp_program__is_attached(prog, iface->ifindex))) {
			ret = libxdp_get_error(prog) ?: -ENOENT;
			pr_debug("Program %s no longer loaded on %s: %s\n",
				 de->d_name, iface->ifname, strerror(-ret));
			err = unlink(pin_path);
			if (err)
				ret = err;
			if (prog)
				xdp_program__close(prog);
		} else {
			if (strcmp(xdp_program__name(prog), de->d_name)) {
				pr_warn("Pinned and kernel prog names differ: %s/%s\n",
					xdp_program__name(prog), de->d_name);
				ret = -EFAULT;
				xdp_program__close(prog);
			} else {
				ret = 0;
				*xdp_prog = prog;
				if (mode)
					*mode = m;
			}
			break;
		}
	}
out:
	closedir(dr);
	return ret;
}

int iterate_pinned_programs(const char *pin_root_path, program_callback cb,
			    void *arg)
{
	char pin_path[PATH_MAX];
	struct dirent *de;
	int err = 0;
	DIR *dr;

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs",
			   pin_root_path);
	if (err)
		return err;

	dr = opendir(pin_path);
	if (!dr)
		return -ENOENT;

	while ((de = readdir(dr)) != NULL) {
		enum xdp_attach_mode mode = XDP_MODE_UNSPEC;
		struct xdp_program *prog = NULL;
		struct iface iface = {};

		if (!strcmp(".", de->d_name) || !strcmp("..", de->d_name))
			continue;

		iface.ifname = de->d_name;
		iface.ifindex = if_nametoindex(iface.ifname);

		err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
				   pin_root_path, iface.ifname);
		if (err)
			goto out;

		err = get_pinned_program(&iface, pin_root_path, &mode, &prog);
		if (err == -ENOENT || err == -ENODEV) {
			err = rmdir(pin_path);
			if (err)
				goto out;
			continue;
		} else if (err) {
			goto out;
		}

		err = cb(&iface, prog, mode, arg);
		xdp_program__close(prog);
		if (err)
			goto out;
	}

out:
	closedir(dr);
	return err;
}

int iterate_iface_multiprogs(multiprog_callback cb, void *arg)
{
	struct if_nameindex *idx, *indexes = NULL;
	int err = 0;

	indexes = if_nameindex();
	if (!indexes) {
		err = -errno;
		pr_warn("Couldn't get list of interfaces: %s\n", strerror(-err));
		return err;
	}

	for (idx = indexes; idx->if_index; idx++) {
		struct xdp_multiprog *mp;
		struct iface iface = {
			.ifindex = idx->if_index,
			.ifname = idx->if_name,
		};

		mp = xdp_multiprog__get_from_ifindex(iface.ifindex);
		if (IS_ERR_OR_NULL(mp)) {
			if (PTR_ERR(mp) != -ENOENT) {
				err = PTR_ERR(mp);
				pr_warn("Error getting XDP status for interface %s: %s\n",
					idx->if_name, strerror(-err));
				goto out;
			}
			mp = NULL;
		}

		err = cb(&iface, mp, arg);
		xdp_multiprog__close(mp);
		if (err)
			goto out;
	}

out:
	if_freenameindex(indexes);
	return err;
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
		strncpy(mnt, mntpt, len - 1);
		mnt[len - 1] = '\0';
		return mnt;
	}

	return NULL;
}

static const char *bpf_find_mntpt(const char *fstype, unsigned long magic,
				  char *mnt, int len,
				  const char * const *known_mnts)
{
	const char * const *ptr;
	char type[100];
	FILE *fp;

	if (known_mnts) {
		ptr = known_mnts;
		while (*ptr) {
			if (bpf_find_mntpt_single(magic, mnt, len, *ptr))
				return mnt;
			ptr++;
		}
	}

	if (len != PATH_MAX)
		return NULL;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return NULL;

	while (fscanf(fp, "%*s %" textify(PATH_MAX) "s %99s %*s %*d %*d\n", mnt,
		      type) == 2) {
		if (strcmp(type, fstype) == 0)
			break;
	}

	fclose(fp);
	if (strcmp(type, fstype) != 0)
		return NULL;

	return mnt;
}

static int bpf_mnt_check_target(const char *target)
{
	int ret;

	ret = mkdir(target, S_IRWXU);
	if (ret && errno != EEXIST) {
		ret = -errno;
		pr_warn("mkdir %s failed: %s\n", target, strerror(-ret));
		return ret;
	}

	return 0;
}
/* simplified version of code from iproute2 */
static const char *bpf_get_work_dir()
{
	static char bpf_tmp[PATH_MAX] = BPF_DIR_MNT;
	static char bpf_wrk_dir[PATH_MAX];
	static const char *mnt;
	static bool bpf_mnt_cached;
	static const char *const bpf_known_mnts[] = {
		BPF_DIR_MNT,
		"/bpf",
		0,
	};
	int ret;

	if (bpf_mnt_cached)
		return mnt;

	mnt = bpf_find_mntpt("bpf", BPF_FS_MAGIC, bpf_tmp, sizeof(bpf_tmp),
			     bpf_known_mnts);
	if (!mnt) {
		mnt = BPF_DIR_MNT;
		ret = bpf_mnt_check_target(mnt);
		if (ret || !bpf_is_valid_mntpt(mnt, BPF_FS_MAGIC)) {
			mnt = NULL;
			goto out;
		}
	}

	strncpy(bpf_wrk_dir, mnt, sizeof(bpf_wrk_dir));
	bpf_wrk_dir[sizeof(bpf_wrk_dir) - 1] = '\0';
	mnt = bpf_wrk_dir;
out:
	bpf_mnt_cached = true;
	return mnt;
}

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir, bool fatal)
{
	const char *bpf_dir;

	bpf_dir = bpf_get_work_dir();
	if (!bpf_dir) {
		logging_print(fatal ? LOG_WARN : LOG_DEBUG,
			      "Could not find BPF working dir - bpffs not mounted?\n");
		return -ENOENT;
	}

	if (subdir)
		return try_snprintf(buf, buf_len, "%s/%s", bpf_dir, subdir);
	else
		return try_snprintf(buf, buf_len, "%s", bpf_dir);
}

int get_pinned_map_fd(const char *bpf_root, const char *map_name,
		      struct bpf_map_info *info)
{
	__u32 info_len = sizeof(*info);
	char buf[PATH_MAX];
	int err;

	err = try_snprintf(buf, sizeof(buf), "%s/%s", bpf_root, map_name);
	if (err)
		return err;

	pr_debug("Getting pinned object from %s\n", buf);
	return get_pinned_object_fd(buf, info, &info_len);
}

int unlink_pinned_map(int dir_fd, const char *map_name)
{
	struct stat statbuf = {};
	int err;

	err = fstatat(dir_fd, map_name, &statbuf, 0);
	if (err && errno == ENOENT) {
		pr_debug("Map name %s not pinned\n", map_name);
		return 0;
	} else if (err) {
		err = -errno;
		pr_warn("Couldn't stat pinned map %s: %s\n",
			map_name, strerror(-err));
		return err;
	}

	pr_debug("Unlinking pinned map %s\n", map_name);
	err = unlinkat(dir_fd, map_name, 0);
	if (err) {
		err = -errno;
		pr_warn("Couldn't unlink pinned map %s: %s\n",
			map_name, strerror(-err));
		return -errno;
	}

	return 0;
}

#define XDP_UNKNOWN (XDP_REDIRECT + 1)
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]   = "XDP_ABORTED",
	[XDP_DROP]      = "XDP_DROP",
	[XDP_PASS]      = "XDP_PASS",
	[XDP_TX]        = "XDP_TX",
	[XDP_REDIRECT]  = "XDP_REDIRECT",
	[XDP_UNKNOWN]	= "XDP_UNKNOWN",
};

const char *action2str(__u32 action)
{
	if (action < XDP_ACTION_MAX)
		return xdp_action_names[action];
	return NULL;
}

int check_bpf_environ(void)
{
	init_lib_logging();

	if (geteuid() != 0) {
		pr_warn("This program must be run as root.\n");
		return 1;
	}

	/* Try to avoid probing errors due to rlimit exhaustion by starting out
	 * with an rlimit of 1 MiB. This is not going to solve all issues, but
	 * it will at least make things work when there is nothing else loaded.
	 *
	 * Ignore return code because an error shouldn't abort running.
	 */
	set_rlimit(1024 * 1024);

	return 0;
}


int prog_lock_acquire(const char *dir)
{
	int lock_fd, err = 0;
retry:
	lock_fd = open(dir, O_DIRECTORY);
	if (lock_fd < 0) {
		if (errno == ENOENT && !mkdir(dir, S_IRWXU))
			goto retry;

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

int prog_lock_release(int lock_fd)
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

static char *print_bpf_tag(char buf[BPF_TAG_SIZE * 2 + 1],
			   const unsigned char tag[BPF_TAG_SIZE])
{
	int i;

	for (i = 0; i < BPF_TAG_SIZE; i++)
		sprintf(&buf[i * 2], "%02x", tag[i]);
	buf[BPF_TAG_SIZE * 2] = '\0';
	return buf;
}

static int print_iface_status(const struct iface *iface,
			      const struct xdp_multiprog *mp,
			      __unused void *arg)
{
	struct xdp_program *prog, *dispatcher, *hw_prog;
	char tag[BPF_TAG_SIZE * 2 + 1];
	char buf[STRERR_BUFSIZE];
	int err;

	if (!mp) {
		printf("%-22s <No XDP program loaded!>\n", iface->ifname);
		return 0;
	}

	hw_prog = xdp_multiprog__hw_prog(mp);
	if (hw_prog) {
		printf("%-16s %-5s %-17s %-8s %-4d %-17s\n",
		       iface->ifname,
		       "",
		       xdp_program__name(hw_prog),
		       get_enum_name(xdp_modes, XDP_MODE_HW),
		       xdp_program__id(hw_prog),
		       print_bpf_tag(tag, xdp_program__tag(hw_prog)));
	}

	dispatcher = xdp_multiprog__main_prog(mp);
	if (dispatcher) {
		printf("%-16s %-5s %-17s %-8s %-4d %-17s\n",
		iface->ifname,
		"",
		xdp_program__name(dispatcher),
		get_enum_name(xdp_modes, xdp_multiprog__attach_mode(mp)),
		xdp_program__id(dispatcher),
		print_bpf_tag(tag, xdp_program__tag(dispatcher)));


		for (prog = xdp_multiprog__next_prog(NULL, mp);
		     prog;
		     prog = xdp_multiprog__next_prog(prog, mp)) {

			err = xdp_program__print_chain_call_actions(prog, buf,
								    sizeof(buf));
			if (err)
				return err;

			printf("%-16s %-5d  %-16s %-8s %-4u %-17s %s\n",
			       " =>", xdp_program__run_prio(prog),
			       xdp_program__name(prog),
			       "", xdp_program__id(prog),
			       print_bpf_tag(tag, xdp_program__tag(prog)),
			       buf);
		}
	}

	return 0;
}

int iface_print_status(const struct iface *iface)
{
	int err = 0;

	printf("%-16s %-5s %-17s Mode     ID   %-17s %s\n",
	       "Interface", "Prio", "Program name", "Tag", "Chain actions");
	printf("--------------------------------------------------------------------------------------\n");

	if (iface) {
		struct xdp_multiprog *mp;

		mp = xdp_multiprog__get_from_ifindex(iface->ifindex);
		if (IS_ERR_OR_NULL(mp)) {
			if (PTR_ERR(mp) != -ENOENT) {
				err = PTR_ERR(mp);
				pr_warn("Error getting XDP status for interface %s: %s\n",
					iface->ifname, strerror(-err));
				goto out;
			}
			mp = NULL;
		}
		print_iface_status(iface, mp, NULL);
	} else {
		err = iterate_iface_multiprogs(print_iface_status, NULL);
	}
	printf("\n");
out:
	return err;
}

int iface_get_xdp_feature_flags(int ifindex, __u64 *feature_flags)
{
#ifdef HAVE_LIBBPF_BPF_XDP_QUERY
	LIBBPF_OPTS(bpf_xdp_query_opts, opts);
	int err;

	err = bpf_xdp_query(ifindex, 0, &opts);
	if (err)
		return err;

	*feature_flags = opts.feature_flags;
	return 0;
#else
	return -EOPNOTSUPP;
#endif

}
