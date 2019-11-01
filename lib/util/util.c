/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
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

static int get_xdp_prog_info(int ifindex, bool skb_mode,
			     struct bpf_prog_info *info)
{
	__u32 prog_id, info_len = sizeof(*info);
	int prog_fd, err = 0, xdp_flags = 0;

	if (skb_mode)
		xdp_flags |= XDP_FLAGS_SKB_MODE;

	err = bpf_get_link_xdp_id(ifindex, &prog_id, xdp_flags);
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

out:
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
