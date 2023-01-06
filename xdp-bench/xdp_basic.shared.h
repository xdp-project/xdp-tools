// SPDX-License-Identifier: GPL-2.0-only

#ifndef _XDP_BASIC_SHARED_H
#define _XDP_BASIC_SHARED_H

enum basic_program_mode {
	BASIC_NO_TOUCH,
	BASIC_READ_DATA,
	BASIC_PARSE_IPHDR,
	BASIC_SWAP_MACS,
};

#endif
