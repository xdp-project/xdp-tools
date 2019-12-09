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

int check_snprintf(char *buf, size_t buf_len, const char *format, ...)
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

int double_rlimit()
{
	struct rlimit limit;
	int err = 0;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't get current rlimit\n");
		return err;
	}

	if (limit.rlim_cur == RLIM_INFINITY) {
		pr_debug("Current rlimit is infinity. Not raising\n");
		return -ENOMEM;
	}

	pr_debug("Doubling current rlimit of %lu\n", limit.rlim_cur);
	limit.rlim_cur <<= 1;
	limit.rlim_max = max(limit.rlim_cur, limit.rlim_max);

	err = setrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't raise rlimit: %s\n", strerror(-err));
		return err;
	}

	return 0;
}

static int __get_xdp_prog_info(int ifindex, struct bpf_prog_info *info, bool *is_skb)
{
	__u32 prog_id, info_len = sizeof(*info);
	struct xdp_link_info xinfo = {};
	int prog_fd, err = 0;

	err = bpf_get_link_xdp_info(ifindex, &xinfo, sizeof(xinfo), 0);
	if (err)
		goto out;

	if (xinfo.attach_mode == XDP_ATTACHED_SKB)
		prog_id = xinfo.skb_prog_id;
	else
		prog_id = xinfo.drv_prog_id;

	if (!prog_id)
		return -ENOENT;

	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0) {
		err = -errno;
		goto out;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, info, &info_len);
	if (err)
		goto out;

	if (is_skb)
		*is_skb = xinfo.attach_mode == XDP_ATTACHED_SKB;

out:
	return err;
}

struct bpf_object *open_bpf_file(const char *progname,
                                 struct bpf_object_open_opts *opts)
{
	static char *bpf_obj_paths[] = {
#ifdef DEBUG
		".",
#endif
		BPF_OBJECT_PATH,
		NULL
	};
	char buf[PATH_MAX], **path;
	struct stat sb = {};
	int err;

	for (path = bpf_obj_paths; *path; path++) {
		err = check_snprintf(buf, sizeof(buf), "%s/%s", *path, progname);
		if (err)
			return ERR_PTR(err);

		pr_debug("Looking for '%s'\n", buf);
		err = stat(buf, &sb);
		if (err)
			continue;

		pr_debug("Loading bpf file '%s' from '%s'\n", progname, buf);
		return bpf_object__open_file(buf, opts);
	}

	pr_warn("Couldn't find a BPF file with name %s\n", progname);
	return ERR_PTR(-ENOENT);
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

static bool program_is_loaded(int ifindex, const char *pin_path, bool *is_skb,
			      struct bpf_prog_info *info)
{
	struct bpf_prog_info if_info = {}, pinned_info = {};
	__u32 info_len = sizeof(if_info);
	int if_fd, pinned_fd;
	bool ret;

	if_fd = __get_xdp_prog_info(ifindex, &if_info, is_skb);
	if (if_fd < 0) {
		return false;
	}

	if (!pin_path) {
		close(if_fd);
		ret = true;
		goto out;
	}

	pinned_fd = get_pinned_object_fd(pin_path, &pinned_info, &info_len);
	if (pinned_fd < 0) {
		close(if_fd);
		return false;
	}

	ret = if_info.id == pinned_info.id;

	close(pinned_fd);
	close(if_fd);

out:
	if (ret && info)
		*info = if_info;

	return ret;
}

int get_loaded_program(const struct iface *iface, bool *is_skb,
		       struct bpf_prog_info *info)
{
	if (!program_is_loaded(iface->ifindex, NULL, is_skb, info))
		return -ENOENT;
	return 0;
}

int get_xdp_prog_info(const struct iface *iface, struct bpf_prog_info *info,
		      bool *is_skb, const char *pin_root_path)
{
	char pin_path[PATH_MAX];
	int err;

	err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
			     pin_root_path, iface->ifname);
	if (err)
		return err;

	if (!program_is_loaded(iface->ifindex, pin_path, is_skb, info))
		return -ENOENT;

	return 0;
}

static int make_dir_subdir(const char *parent, const char *dir)
{
	char path[PATH_MAX];
	int err;

	err = check_snprintf(path, sizeof(path), "%s/%s", parent, dir);
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

int attach_xdp_program(const struct bpf_object *obj, const char *prog_name,
		       const struct iface *iface, bool force, bool skb_mode,
		       const char *pin_root_path)
{
	char pin_path[PATH_MAX], old_prog_name[100];
	int ifindex = iface->ifindex;
	int err = 0, xdp_flags = 0;
	struct bpf_program *prog;
	struct stat sb = {};
	bool has_old;
	int prog_fd;

	err = make_dir_subdir(pin_root_path, "programs");
	if (err)
		return err;

	err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s/%s",
			     pin_root_path, iface->ifname, prog_name);
	if (err)
		return err;

	err = get_pinned_program(iface, pin_root_path, old_prog_name,
				sizeof(old_prog_name), NULL, NULL);
	has_old = err != -ENOENT;

	if (!force) {
		if (has_old) {
			pr_warn("Program already loaded on %s; use --force to replace\n",
				iface->ifname);
			return -EEXIST;
		}

		xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	} else if (!has_old && program_is_loaded(ifindex, NULL, NULL, NULL)) {
		pr_warn("Found an XDP program on %s, but not installed by us. "
			"Refusing to replace; remove manually and try again\n",
			iface->ifname);
		return -EEXIST;
	} else if (has_old) {
		pr_debug("Replacing old program '%s' on iface '%s'\n",
			 old_prog_name, iface->ifname);
	}

	if (skb_mode)
		xdp_flags |= XDP_FLAGS_SKB_MODE;

	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (!prog)
		prog = bpf_program__next(NULL, obj);

	if (!prog) {
		pr_warn("Couldn't find an eBPF program '%s' to attach. "
			"This is a bug!\n", prog_name);
		return -EFAULT;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd <= 0) {
		pr_warn("Invalid prog fd %d\n", prog_fd);
		return -EFAULT;
	}

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= skb_mode ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}
	if (err < 0) {
		pr_warn("Error attaching XDP program to %s: %s\n",
			iface->ifname, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			pr_warn("XDP already loaded on device;"
				" use --force to replace\n");
			break;
		case EOPNOTSUPP:
			pr_warn("Native XDP not supported;"
				" try using --skb-mode\n");
			break;
		default:
			break;
		}
		return err;
	}

	pr_debug("Program '%s' loaded on interface '%s'%s\n",
		 prog_name, iface->ifname, skb_mode ? " in skb mode" : "");

	if (has_old) {
		char buf[PATH_MAX];
		err = check_snprintf(buf, sizeof(buf), "%s/programs/%s/%s",
				     pin_root_path, iface->ifname, old_prog_name);
		if (!err) {
			pr_debug("Unpinning old program from %s\n", buf);
			unlink(buf);
		}
	}

	err = stat(pin_path, &sb);
	if (!err)
		unlink(pin_path);

	err = bpf_program__pin(prog, pin_path);
	if (err) {
		pr_warn("Unable to pin XDP program at %s: %s\n",
			pin_path, strerror(-err));
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	}
	pr_debug("XDP program pinned at %s\n", pin_path);

	return err;
}

int detach_xdp_program(const struct iface *iface, const char *pin_root_path)
{
	char pin_path[PATH_MAX], prog_name[100];
	int err;

	err = get_pinned_program(iface, pin_root_path, prog_name,
				 sizeof(prog_name), NULL, NULL);
	if (err) {
		pr_warn("No XDP program loaded on %s\n", iface->ifname);
		return -ENOENT;
	}

	err = bpf_set_link_xdp_fd(iface->ifindex, -1, 0);
	if (err)
		goto out;

	err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s/%s",
			     pin_root_path, iface->ifname, prog_name);
	if (err)
		return err;

	err = unlink(pin_path);
	if (err)
		goto out;

	err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
			     pin_root_path, iface->ifname, prog_name);
	if (err)
		goto out;

	err = rmdir(pin_path);
out:
	return err;
}

int get_pinned_program(const struct iface *iface, const char *pin_root_path,
		       char *prog_name, size_t prog_name_len, bool *is_skb,
		       struct bpf_prog_info *info)
{
	int ret = -ENOENT, err, ifindex = iface->ifindex;
	char pin_path[PATH_MAX];
	bool remove_all = false;
	struct dirent *de;
	DIR *dr;

	err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
			     pin_root_path, iface->ifname);
	if (err)
		return err;

	dr = opendir(pin_path);
	if (!dr)
		return -ENOENT;

	if (!ifindex)
		ifindex = if_nametoindex(iface->ifname);
	if (!ifindex) {
		pr_debug("Interface %s no longer exists\n", iface->ifname);
		remove_all = true;
		ret = -ENODEV;
	}

	while ((de = readdir(dr)) != NULL) {
		if (!strcmp(".", de->d_name) ||
		    !strcmp("..", de->d_name))
			continue;

		err = check_snprintf(pin_path, sizeof(pin_path),
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

		if (!program_is_loaded(iface->ifindex, pin_path, is_skb, info)) {
			ret = -ENOENT;
			pr_debug("Program %s no longer loaded on %s\n",
				 de->d_name, iface->ifname);
			err = unlink(pin_path);
			if (err)
				ret = err;
		} else {
			ret = 0;
			err = check_snprintf(prog_name, prog_name_len, "%s",
					     de->d_name);
			if (err)
				ret = err;
			if (strcmp(prog_name, info->name)) {
				pr_warn("Pinned and kernel prog names differ: %s/%s\n",
					prog_name, info->name);
				ret = -E2BIG;
			}
			break;
		}
	}
out:
	closedir(dr);
	return ret;
}

int iterate_iface_programs_pinned(const char *pin_root_path,
				  program_callback cb, void *arg)
{
	char pin_path[PATH_MAX];
	struct dirent *de;
	int err = 0;
	DIR *dr;

	err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs",
			     pin_root_path);
	if (err)
		return err;

	dr = opendir(pin_path);
	if (!dr)
		return -ENOENT;

	while ((de = readdir(dr)) != NULL) {
		struct bpf_prog_info info = {};
		char prog_name[PATH_MAX];
		struct iface iface = {};
		bool is_skb;

		if (!strcmp(".", de->d_name) ||
		    !strcmp("..", de->d_name))
			continue;

		iface.ifname = de->d_name;
		iface.ifindex = if_nametoindex(iface.ifname);

		err = check_snprintf(pin_path, sizeof(pin_path), "%s/programs/%s",
				     pin_root_path, iface.ifname);
		if (err)
			goto out;

		err = get_pinned_program(&iface, pin_root_path,
					 prog_name, sizeof(prog_name), &is_skb, &info);

		if (err == -ENOENT || err == -ENODEV) {
			err = rmdir(pin_path);
			if (err)
				goto out;
			continue;
		} else if (err) {
			goto out;
		}

		err = cb(&iface, &info, is_skb, arg);
		if (err)
			goto out;
	}

out:
	closedir(dr);
	return err;
}

int iterate_iface_programs_all(const char *pin_root_path,
			       program_callback cb, void *arg)
{
	struct if_nameindex *idx, *indexes = NULL;
	int err = 0;

	indexes = if_nameindex();
	if (!indexes) {
		err = -errno;
		pr_warn("Couldn't get list of interfaces: %s\n", strerror(-err));
		goto out;
	}

	for (idx = indexes; idx->if_index; idx++){
		struct bpf_prog_info info = {};
		struct iface iface = {
			.ifindex = idx->if_index,
			.ifname = idx->if_name,
		};
		bool is_skb;


		if (!program_is_loaded(iface.ifindex, NULL, &is_skb, &info))
			continue;

		err = cb(&iface, &info, is_skb, arg);
		if (err)
			goto out;
	}

out:
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
		strncpy(mnt, mntpt, len);
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
	struct stat sb = {};
	int ret;

	ret = stat(target, &sb);
	if (ret) {
		ret = mkdir(target, S_IRWXU);
		if (ret) {
			pr_warn("mkdir %s failed: %s\n", target, strerror(errno));
			return ret;
		}
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

	if (subdir)
		return check_snprintf(buf, buf_len, "%s/%s", bpf_dir, subdir);
	else
		return check_snprintf(buf, buf_len, "%s", bpf_dir);
}

int get_pinned_map_fd(const char *bpf_root, const char *map_name,
		      struct bpf_map_info *info)
{
	__u32 info_len = sizeof(*info);
	char buf[PATH_MAX];
	int err;

	err = check_snprintf(buf, sizeof(buf), "%s/%s", bpf_root, map_name);
	if (err)
		return err;

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
	init_libbpf_logging();

	if (geteuid() != 0) {
		pr_warn("This program must be run as root.\n");
		return 1;
	}

	if (!pin_root_path) {
		pr_warn("Couldn't find a valid bpffs. "
			"Please mount bpffs at %s\n", BPF_DIR_MNT);
		return 1;
	}

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
		err = check_snprintf(buf, sizeof(buf), "%s/%s.lck", lock_dir,
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
	    sigaction(SIGTERM, &sigact, NULL)) {
		err = -errno;
		pr_warn("Unable to install signal handler: %s\n", strerror(-err));
		return err;
	}

	prog_lock_fd = open(prog_lock_file, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (prog_lock_fd < 0) {
		err = -errno;
		if (err == -EEXIST) {
			unsigned long pid;
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

			len = read(fd, buf, sizeof(buf));
			close(fd);
			buf[len] = '\0';

			pid = strtoul(buf, NULL, 10);
			if (!pid) {
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
