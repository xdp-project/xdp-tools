/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>

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
