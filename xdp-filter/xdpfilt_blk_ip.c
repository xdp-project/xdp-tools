/* SPDX-License-Identifier: GPL-2.0 */

#define FILT_MODE_BLACKLIST
#undef FILT_MODE_ETHERNET
#define FILT_MODE_IPV4
#define FILT_MODE_IPV6
#undef FILT_MODE_UDP
#undef FILT_MODE_TCP
#define FUNCNAME xdpfilt_blk_ip
#include "xdpfilt_prog.h"
