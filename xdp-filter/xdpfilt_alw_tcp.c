/* SPDX-License-Identifier: GPL-2.0 */

#define FILT_MODE_ALLOW
#undef FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#undef FILT_MODE_UDP
#define FILT_MODE_TCP
#define FUNCNAME xdpfilt_alw_tcp
#include "xdpfilt_prog.h"
