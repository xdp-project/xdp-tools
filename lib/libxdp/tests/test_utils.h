/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __TEST_UTILS_H
#define __TEST_UTILS_H

#include <bpf/libbpf.h>

#define __unused __attribute__((unused))

static int libbpf_silent_func(__unused enum libbpf_print_level level,
			      __unused const char *format,
			      __unused va_list args)
{
	return 0;
}

static void silence_libbpf_logging(void)
{
	libbpf_set_print(libbpf_silent_func);
}

#endif
