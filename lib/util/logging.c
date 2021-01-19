/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdarg.h>

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "logging.h"
#include "util.h"

static enum logging_print_level log_level = LOG_INFO;

static int print_func(enum logging_print_level level, const char *format,
		      va_list args)
{
	if (level > log_level)
		return 0;

	return vfprintf(stderr, format, args);
}

static int libbpf_print_func(enum libbpf_print_level level, const char *format,
			     va_list args)
{
	return print_func(level + 1, format, args);
}

static int libbpf_silent_func(__unused enum libbpf_print_level level,
			      __unused const char *format,
			      __unused va_list args)
{
	return 0;
}

static int libxdp_print_func(enum libxdp_print_level level, const char *format,
			     va_list args)
{
	return print_func(level + 1, format, args);
}

static int libxdp_silent_func(__unused enum libxdp_print_level level,
			      __unused const char *format,
			      __unused va_list args)
{
	return 0;
}

#define __printf(a, b) __attribute__((format(printf, a, b)))

__printf(2, 3) void logging_print(enum logging_print_level level,
				  const char *format, ...)
{
	va_list args;

	va_start(args, format);
	print_func(level, format, args);
	va_end(args);
}

void init_lib_logging(void)
{
	libbpf_set_print(libbpf_print_func);
	libxdp_set_print(libxdp_print_func);
}

void silence_libbpf_logging(void)
{
	if (log_level < LOG_VERBOSE)
		libbpf_set_print(libbpf_silent_func);
}

void silence_libxdp_logging(void)
{
	if (log_level < LOG_VERBOSE)
		libxdp_set_print(libxdp_silent_func);
}

enum logging_print_level set_log_level(enum logging_print_level level)
{
	enum logging_print_level old_level = log_level;

	log_level = level;
	return old_level;
}

enum logging_print_level increase_log_level(void)
{
	if (log_level < LOG_VERBOSE)
		log_level++;
	return log_level;
}
