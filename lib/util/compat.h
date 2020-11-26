#ifndef __COMPAT_H
#define __COMPAT_H

#ifndef HAVE_SECURE_GETENV
#include <stdlib.h>
// Source: https://www.openwall.com/lists/musl/2019/05/28/3
static inline char *secure_getenv(const char *name)
{
	return libc.secure ? NULL : getenv(name);
}
#endif

#endif
