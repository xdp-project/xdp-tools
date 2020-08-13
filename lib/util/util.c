/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
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
			pr_debug("Current rlimit %lu already >= minimum %u\n",
				 limit.rlim_cur, min_limit);
			return 0;
		}
                pr_debug("Setting rlimit to minimum %u\n", min_limit);
		limit.rlim_cur = min_limit;
        } else {
		pr_debug("Doubling current rlimit of %lu\n", limit.rlim_cur);
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

int double_rlimit()
{
	pr_debug("Permission denied when loading eBPF object; "
		 "raising rlimit and retrying\n");

	return set_rlimit(0);
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
	struct stat sb = {};
	char **path;
	int err;

	for (path = bpf_obj_paths; *path; path++) {
		err = try_snprintf(buf, buf_size, "%s/%s", *path, progname);
		if (err)
			return err;

		pr_debug("Looking for '%s'\n", buf);
		err = stat(buf, &sb);
		if (err)
			continue;

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
		pr_warn("Unable to create pin directory: %s\n",
			strerror(-err));
		return err;
	}

	err = try_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s/%s",
			   pin_root_path, iface->ifname,
			     xdp_program__name(prog));
	if (err)
		return err;

	err = xdp_program__attach(prog, iface->ifindex, mode);
	if (err) {
		if (pin_root_path && err != -EEXIST)
			unlink(pin_path);
		return err;
	}

	pr_debug("Program '%s' loaded on interface '%s'%s\n",
		 xdp_program__name(prog),
		 iface->ifname,
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
	xdp_program__detach(prog, iface->ifindex, mode);
	return err;
}

int detach_xdp_program(struct xdp_program *prog, const struct iface *iface,
		       enum xdp_attach_mode mode, const char *pin_root_path)
{
	char pin_path[PATH_MAX];
	int err;

	err = xdp_program__detach(prog, iface->ifindex, mode);
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
		struct xdp_program *prog;

		if (!strcmp(".", de->d_name) ||
		    !strcmp("..", de->d_name))
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

		prog = xdp_program__from_pin(pin_path);
		if (IS_ERR_OR_NULL(prog) ||
		    !(m = xdp_program__is_attached(prog, iface->ifindex))) {
			ret = IS_ERR(prog) ? PTR_ERR(prog) : -ENOENT;
			pr_debug("Program %s no longer loaded on %s: %s\n",
				 de->d_name, iface->ifname, strerror(-ret));
			err = unlink(pin_path);
			if (err)
				ret = err;
			if (!IS_ERR_OR_NULL(prog))
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

int iterate_pinned_programs(const char *pin_root_path,
			    program_callback cb, void *arg)
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

		if (!strcmp(".", de->d_name) ||
		    !strcmp("..", de->d_name))
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

	for (idx = indexes; idx->if_index; idx++){
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
		strncpy(mnt, mntpt, len-1);
		mnt[len-1] = '\0';
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

	while (fscanf(fp, "%*s %" textify(PATH_MAX) "s %99s %*s %*d %*d\n",
		      mnt, type) == 2) {
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
	static const char * const bpf_known_mnts[] = {
		BPF_DIR_MNT,
		"/bpf",
		0,
	};
	int ret;

	if (bpf_mnt_cached)
		return mnt;

	mnt = bpf_find_mntpt("bpf", BPF_FS_MAGIC, bpf_tmp,
			     sizeof(bpf_tmp), bpf_known_mnts);
	if (!mnt) {
		mnt = BPF_DIR_MNT;
		ret = bpf_mnt_check_target(mnt);
		if (ret || !bpf_is_valid_mntpt(mnt, BPF_FS_MAGIC)) {
			mnt = NULL;
			goto out;
		}
	}

	strncpy(bpf_wrk_dir, mnt, sizeof(bpf_wrk_dir));
	bpf_wrk_dir[sizeof(bpf_wrk_dir) -1] = '\0';
	mnt = bpf_wrk_dir;
out:
	bpf_mnt_cached = true;
	return mnt;
}

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir)
{
	const char *bpf_dir;

	bpf_dir = bpf_get_work_dir();
	if (!bpf_dir) {
		pr_warn("Could not find BPF working dir - bpffs not mounted?\n");
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

#define XDP_UNKNOWN	XDP_REDIRECT + 1
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

int check_bpf_environ(const char *pin_root_path)
{
	init_lib_logging();

	if (geteuid() != 0) {
		pr_warn("This program must be run as root.\n");
		return 1;
	}

	if (!pin_root_path) {
		pr_warn("Couldn't find a valid bpffs. "
			"Please mount bpffs at %s\n", BPF_DIR_MNT);
		return 1;
	}

	/* Try to avoid probing errors due to rlimit exhaustion by starting out
	 * with an rlimit of 1 MiB. This is not going to solve all issues, but
	 * it will at least make things work when there is nothing else loaded.
	 *
	 * Ignore return code because an error shouldn't abort running.
	 */
	set_rlimit(1024*1024);

	return 0;
}

static const char *lock_dir = "/run";
static char *prog_lock_file = NULL;
static int prog_lock_fd = -1;
static pid_t prog_pid = 0;

void prog_lock_release(int signal)
{
	int err;
	struct sigaction sigact = {
		.sa_flags = SA_RESETHAND
	};


	if (prog_lock_fd < 0 || !prog_lock_file)
		return;

	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGSEGV, &sigact, NULL);
	sigaction(SIGFPE, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	err = unlink(prog_lock_file);
	if (err) {
		err = -errno;
		pr_warn("Unable to unlink lock file: %s\n", strerror(-err));
		goto out;
	}

	close(prog_lock_fd);
	free(prog_lock_file);
	prog_lock_fd = -1;
	prog_lock_file = NULL;

out:
	if (signal) {
		pr_debug("Exiting on signal %d\n", signal);
		if (prog_pid)
			kill(prog_pid, signal);
		else
			exit(signal);
	}
}


int prog_lock_get(const char *progname)
{
	char buf[PATH_MAX];
	int err;
	struct sigaction sigact = {
		.sa_handler = prog_lock_release
	};

	if (prog_lock_fd >= 0) {
		pr_warn("Attempt to get prog_lock twice.\n");
		return -EFAULT;
	}

	if (!prog_lock_file) {
		err = try_snprintf(buf, sizeof(buf), "%s/%s.lck", lock_dir,
				   progname);
		if (err)
			return err;

		prog_lock_file = strdup(buf);
		if (!prog_lock_file)
			return -ENOMEM;
	}

	prog_pid = getpid();

	if (sigaction(SIGHUP, &sigact, NULL) ||
	    sigaction(SIGINT, &sigact, NULL) ||
	    sigaction(SIGSEGV, &sigact, NULL) ||
	    sigaction(SIGFPE, &sigact, NULL) ||
	    sigaction(SIGTERM, &sigact, NULL)) {
		err = -errno;
		pr_warn("Unable to install signal handler: %s\n", strerror(-err));
		return err;
	}

	prog_lock_fd = open(prog_lock_file, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (prog_lock_fd < 0) {
		err = -errno;
		if (err == -EEXIST) {
			unsigned long pid = 0;
			char buf[100];
			ssize_t len;
			int fd;

			fd = open(prog_lock_file, O_RDONLY);
			if (fd < 0) {
				err = -errno;
				pr_warn("Unable to open lockfile for reading: %s\n",
					strerror(-err));
				return err;
			}

			len = read(fd, buf, sizeof(buf)-1);
			close(fd);
			if (len > 0) {
				buf[len] = '\0';
				pid = strtoul(buf, NULL, 10);
			}
			if (!pid || errno) {
				err = -errno;
				pr_warn("Unable to read PID from lockfile: %s\n",
					strerror(-err));
				return err;
			}
			pr_warn("Unable to get program lock: Already held by pid %lu\n",
				pid);
		} else {
			pr_warn("Unable to get program lock: %s\n", strerror(-err));
		}
		return err;
	}

	err = dprintf(prog_lock_fd, "%d\n", prog_pid);
	if (err < 0) {
		err = -errno;
		pr_warn("Unable to write pid to lock file: %s\n", strerror(-err));
		goto out_err;
	}

	err = fsync(prog_lock_fd);
	if (err) {
		err = -errno;
		pr_warn("Unable fsync() lock file: %s\n", strerror(-err));
		goto out_err;
	}

	return 0;
out_err:
	unlink(prog_lock_file);
	close(prog_lock_fd);
	free(prog_lock_file);
	prog_lock_file = NULL;
	prog_lock_fd = -1;
	return err;
}
