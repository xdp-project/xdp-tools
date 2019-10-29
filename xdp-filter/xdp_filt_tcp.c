/* SPDX-License-Identifier: GPL-2.0 */

#undef FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#undef FILT_MODE_UDP
#define FILT_MODE_TCP
#include "xdp_filt_prog.h"
