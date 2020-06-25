/* SPDX-License-Identifier: GPL-2.0 */

#define FILT_MODE_DENY
#undef FILT_MODE_ETHERNET
#define FILT_MODE_IPV4
#define FILT_MODE_IPV6
#undef FILT_MODE_UDP
#undef FILT_MODE_TCP
#define FUNCNAME xdpfilt_dny_ip
#include "xdpfilt_prog.h"
