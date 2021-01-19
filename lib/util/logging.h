/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LOGGING_H
#define __LOGGING_H

/* This matches the libbpf logging levels, but with an additional VERBOSE level;
 * we demote all libbpf messages by one level so debug messages only show up on
 * VERBOSE.
 */
enum logging_print_level {
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_VERBOSE,
};

extern void logging_print(enum logging_print_level level, const char *format,
			  ...) __attribute__((format(printf, 2, 3)));

#define __pr(level, fmt, ...)                             \
	do {                                              \
		logging_print(level, fmt, ##__VA_ARGS__); \
	} while (0)

#define pr_warn(fmt, ...) __pr(LOG_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) __pr(LOG_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) __pr(LOG_DEBUG, fmt, ##__VA_ARGS__)

void init_lib_logging(void);
void silence_libbpf_logging(void);
void silence_libxdp_logging(void);
enum logging_print_level set_log_level(enum logging_print_level level);
enum logging_print_level increase_log_level();

#endif
