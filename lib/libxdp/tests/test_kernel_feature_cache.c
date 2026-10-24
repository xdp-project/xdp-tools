// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <xdp/libxdp.h>

static int debug_messages;

static int count_debug(enum libxdp_print_level level, const char *format,
                       va_list args)
{
	(void)format;
	(void)args;

	if (level == LIBXDP_DEBUG)
		debug_messages++;
	return 0;
}

int main(void)
{
	libxdp_print_fn_t old_print;
	int first_probe_messages;

	old_print = libxdp_set_print(count_debug);
	libxdp_cache_kernel_features();
	first_probe_messages = debug_messages;
	if (!first_probe_messages)
		return 1;

	libxdp_cache_kernel_features();
	if (debug_messages != first_probe_messages)
		return 2;

	libxdp_set_print(old_print);
	return 0;
}
