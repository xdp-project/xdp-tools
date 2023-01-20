/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __TEST_UTILS_H
#define __TEST_UTILS_H

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#define __unused __attribute__((unused))

static int libbpf_silent_func(__unused enum libbpf_print_level level,
			      __unused const char *format,
			      __unused va_list args)
{
	return 0;
}

static inline void silence_libbpf_logging(void)
{
	libbpf_set_print(libbpf_silent_func);
}

static int libxdp_silent_func(__unused enum libxdp_print_level level,
			      __unused const char *format,
			      __unused va_list args)
{
	return 0;
}

static int libxdp_verbose_func(__unused enum libxdp_print_level level,
			       __unused const char *format,
			       __unused va_list args)
{
	fprintf(stderr, "  ");
	vfprintf(stderr, format, args);
	return 0;
}

static inline void silence_libxdp_logging(void)
{
	libxdp_set_print(libxdp_silent_func);
}

static inline void verbose_libxdp_logging(void)
{
	libxdp_set_print(libxdp_verbose_func);
}

#endif
