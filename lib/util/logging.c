/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdarg.h>

#include "libbpf.h"

#include "logging.h"

static enum logging_print_level log_level = LOG_INFO;

static int print_func(enum libbpf_print_level level, const char *format,
		      va_list args)
{
	if ((enum logging_print_level)level > log_level)
		return 0;

	return vfprintf(stderr, format, args);
}

static int silent_print_func(enum libbpf_print_level level, const char *format,
			     va_list args)
{
	return 0;
}


#define __printf(a, b)	__attribute__((format(printf, a, b)))

__printf(2, 3)
void logging_print(enum logging_print_level level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	print_func(level, format, args);
	va_end(args);
}

void init_libbpf_logging()
{
	libbpf_set_print(print_func);
}

void silence_libbpf_logging()
{
	if (log_level < LOG_DEBUG)
		libbpf_set_print(silent_print_func);
}

enum logging_print_level set_log_level(enum logging_print_level level)
{
	enum logging_print_level old_level = log_level;

	log_level = level;
	return old_level;
}
