#ifndef __LIBXDP_LIBXDP_INTERNAL_H
#define __LIBXDP_LIBXDP_INTERNAL_H

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <linux/err.h>
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
#define __pr(level, fmt, ...)					    \
	do {							    \
		libxdp_print(level, "libxdp: " fmt, ##__VA_ARGS__); \
	} while (0)

#define pr_warn(fmt, ...) __pr(LIBXDP_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) __pr(LIBXDP_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) __pr(LIBXDP_DEBUG, fmt, ##__VA_ARGS__)

LIBXDP_HIDE_SYMBOL int check_xdp_prog_version(const struct btf *btf, const char *name,
					      __u32 *version);

LIBXDP_HIDE_SYMBOL int libxdp_check_kern_compat(void);

#define min(x, y) ((x) < (y) ? x : y)
#define max(x, y) ((x) > (y) ? x : y)

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type *)0)->member)
#endif

#ifndef offsetofend
#define offsetofend(TYPE, FIELD) (offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif

#ifndef container_of
#define container_of(ptr, type, member)				   \
	({							   \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

/* OPTS macros, from libbpf_internal.h */

static inline bool libxdp_is_mem_zeroed(const char *obj,
					size_t off_start, size_t off_end)
{
	const char *p;

	for (p = obj + off_start; p < obj + off_end; p++) {
		if (*p)
			return false;
	}
	return true;
}

static inline bool libxdp_validate_opts(const char *opts,
					size_t opts_sz, size_t user_sz,
					const char *type_name)
{
	if (user_sz < sizeof(size_t)) {
		pr_warn("%s size (%zu) is too small\n", type_name, user_sz);
		return false;
	}
	if (!libxdp_is_mem_zeroed(opts, opts_sz, user_sz)) {
		pr_warn("%s has non-zero extra bytes\n", type_name);
		return false;
	}
	return true;
}

#define OPTS_VALID(opts, type)						      \
	(!(opts) || libxdp_validate_opts((const char *)opts,		      \
					 offsetofend(struct type,	      \
						     type##__last_field),     \
					 (opts)->sz, #type))
#define OPTS_HAS(opts, field) \
	((opts) && opts->sz >= offsetofend(typeof(*(opts)), field))
#define OPTS_GET(opts, field, fallback_value) \
	(OPTS_HAS(opts, field) ? (opts)->field : fallback_value)
#define OPTS_SET(opts, field, value)		\
	do {					\
		if (OPTS_HAS(opts, field))	\
			(opts)->field = value;	\
	} while (0)

#define OPTS_ZEROED(opts, last_nonzero_field)				      \
	(!(opts) || libxdp_is_mem_zeroed((const void *)opts,		      \
					 offsetofend(typeof(*(opts)),	      \
						     last_nonzero_field),     \
					 (opts)->sz))

/* handle direct returned errors */
static inline int libxdp_err(int ret)
{
	if (ret < 0)
		errno = -ret;
	return ret;
}

/* handle error for pointer-returning APIs, err is assumed to be < 0 always */
static inline void *libxdp_err_ptr(int err, bool ret_null)
{
	/* set errno on error, this doesn't break anything */
	errno = -err;

	if (ret_null)
		return NULL;
	/* legacy: encode err as ptr */
	return ERR_PTR(err);
}

LIBXDP_HIDE_SYMBOL int xdp_lock_acquire(void);
LIBXDP_HIDE_SYMBOL int xdp_lock_release(int lock_fd);
LIBXDP_HIDE_SYMBOL int xdp_attach_fd(int prog_fd, int old_fd, int ifindex,
				     enum xdp_attach_mode mode);

#endif /* __LIBXDP_LIBXDP_INTERNAL_H */
