/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <bsd/string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <linux/if_link.h> /* Need XDP flags */
#include <linux/magic.h> /* BPF FS magic */

#include "bpf.h"

#include "util.h"
#include "logging.h"

int check_bpf_environ(unsigned long min_rlimit)
{
	struct rlimit limit;
	int err;

	if (geteuid() != 0) {
		pr_warn("This program must be run as root.\n");
		return 1;
	}

	if (!min_rlimit)
		return 0;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't get current rlimit\n");
		return err;
	}

	if (limit.rlim_cur < min_rlimit) {
		pr_debug("Current rlimit %lu < needed %lu; raising.\n",
			 limit.rlim_cur, min_rlimit);
		limit.rlim_cur = min_rlimit;
		limit.rlim_max = min_rlimit;
		err = setrlimit(RLIMIT_MEMLOCK, &limit);
		if (err) {
			err = -errno;
			pr_warn("Couldn't get current rlimit\n");
			return err;
		}
	}

	return 0;
}

int get_xdp_prog_info(int ifindex, struct bpf_prog_info *info)
{
	__u32 prog_id, info_len = sizeof(*info);
	int prog_fd, err = 0;

	err = bpf_get_link_xdp_id(ifindex, &prog_id, 0);
	if (err)
		goto out;

	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd <= 0) {
		err = -errno;
		goto out;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, info, &info_len);
	if (err)
		goto out;

out:
	return err;
}

int load_xdp_program(struct bpf_program *prog, int ifindex,
		     bool force, bool skb_mode)
{
	int err = 0, xdp_flags = 0;
	int prog_fd;

	if (!force)
		xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

	if (skb_mode)
		xdp_flags |= XDP_FLAGS_SKB_MODE;

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
		pr_warn("ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			pr_warn("XDP already loaded on device"
				" use --force to replace\n");
			break;
		case EOPNOTSUPP:
			pr_warn("Hint: Native XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return -EFAULT;
	}

	return err;
}

static int bpf_valid_mntpt(const char *mnt, unsigned long magic)
{
	struct statfs st_fs;

	if (statfs(mnt, &st_fs) < 0)
		return -ENOENT;
	if ((unsigned long)st_fs.f_type != magic)
		return -ENOENT;

	return 0;
}

static const char *bpf_find_mntpt_single(unsigned long magic, char *mnt,
					 int len, const char *mntpt)
{
	int ret;

	ret = bpf_valid_mntpt(mntpt, magic);
	if (!ret) {
		strlcpy(mnt, mntpt, len);
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
			fprintf(stderr, "mkdir %s failed: %s\n", target,
				strerror(errno));
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
		if (ret) {
			mnt = NULL;
			goto out;
		}
	}

	strlcpy(bpf_wrk_dir, mnt, sizeof(bpf_wrk_dir));
	mnt = bpf_wrk_dir;
out:
	bpf_mnt_cached = true;
	return mnt;
}

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir)
{
	const char *bpf_dir;
	size_t len;

	bpf_dir = bpf_get_work_dir();

	if (subdir)
		len = snprintf(buf, buf_len, "%s/%s", bpf_dir, subdir);
	else
		len = snprintf(buf, buf_len, "%s", bpf_dir);

	if (len < 0)
		return -EINVAL;
	else if (len >= buf_len)
		return -ENAMETOOLONG;

	return 0;
}

int get_pinned_map_fd(const char *bpf_root, const char *map_name,
		      struct bpf_map_info *info)
{
	char buf[PATH_MAX], errmsg[STRERR_BUFSIZE];
	__u32 info_len = sizeof(*info);
	int len, err, pin_fd;

	len = snprintf(buf, sizeof(buf), "%s/%s", bpf_root, map_name);
	if (len < 0)
		return -EINVAL;
	else if (len >= sizeof(buf))
		return -ENAMETOOLONG;

	pin_fd = bpf_obj_get(buf);
	if (pin_fd < 0) {
		err = -errno;
		libbpf_strerror(-err, errmsg, sizeof(errmsg));
		pr_debug("Couldn't retrieve pinned map '%s': %s\n", buf, errmsg);
		return err;
	}

	if (info) {
		err = bpf_obj_get_info_by_fd(pin_fd, info, &info_len);
		if (err) {
			err = -errno;
			libbpf_strerror(-err, errmsg, sizeof(errmsg));
			pr_debug("Couldn't retrieve map info: %s\n", errmsg);
			return err;
		}
	}

	return pin_fd;
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

int check_map_fd_info(const struct bpf_map_info *info,
		      const struct bpf_map_info *exp)
{
	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return -EINVAL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return -EINVAL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return -EINVAL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return -EINVAL;
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

	sigaction(signal, &sigact, NULL);

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
	int err, len;
	struct sigaction sigact = {
		.sa_handler = prog_lock_release
	};

	if (prog_lock_fd >= 0) {
		pr_warn("Attempt to get prog_lock twice.\n");
		return -EFAULT;
	}

	if (!prog_lock_file) {
		len = snprintf(buf, sizeof(buf), "%s/%s.lck", lock_dir, progname);
		if (len < 0)
			return -EINVAL;
		else if (len >= sizeof(buf))
			return -ENAMETOOLONG;

		prog_lock_file = strdup(buf);
		if (!prog_lock_file)
			return -ENOMEM;
	}

	prog_pid = getpid();

	if (sigaction(SIGHUP, &sigact, NULL) ||
	    sigaction(SIGINT, &sigact, NULL) ||
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
