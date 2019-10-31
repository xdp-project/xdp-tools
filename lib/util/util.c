/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <unistd.h>
#include <string.h>     /* strerror */
#include <sys/resource.h>
#include <linux/if_link.h> /* Need XDP flags */

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
