#ifndef __LIBXDP_LIBXDP_INTERNAL_H
#define __LIBXDP_LIBXDP_INTERNAL_H

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <xdp/libxdp.h>

#define LIBXDP_HIDE_SYMBOL __attribute__((visibility("hidden")))
#define __unused __attribute__((unused))

#define __printf(a, b) __attribute__((format(printf, a, b)))

static inline int try_snprintf(char *buf, size_t buf_len, const char *format, ...)
{
	va_list args;
	int len;

	va_start(args, format);
	len = vsnprintf(buf, buf_len, format, args);
	va_end(args);

	if (len < 0)
		return -EINVAL;
	else if ((size_t)len >= buf_len)
		return -ENAMETOOLONG;

	return 0;
}

LIBXDP_HIDE_SYMBOL __printf(2, 3) void libxdp_print(enum libxdp_print_level level,
						    const char *format, ...);
#define __pr(level, fmt, ...)                                       \
	do {                                                        \
		libxdp_print(level, "libxdp: " fmt, ##__VA_ARGS__); \
	} while (0)

#define pr_warn(fmt, ...) __pr(LIBXDP_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) __pr(LIBXDP_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) __pr(LIBXDP_DEBUG, fmt, ##__VA_ARGS__)

LIBXDP_HIDE_SYMBOL int check_xdp_prog_version(const struct btf *btf, const char *name,
					      __u32 *version);
LIBXDP_HIDE_SYMBOL struct xdp_program *xdp_program__clone(struct xdp_program *prog);

#define min(x, y) ((x) < (y) ? x : y)
#define max(x, y) ((x) > (y) ? x : y)

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#endif /* __LIBXDP_LIBXDP_INTERNAL_H */
