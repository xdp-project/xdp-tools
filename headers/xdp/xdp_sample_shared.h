// SPDX-License-Identifier: GPL-2.0-only
#ifndef _XDP_SAMPLE_SHARED_H
#define _XDP_SAMPLE_SHARED_H

struct datarec {
	unsigned long long processed;
	unsigned long long dropped;
	unsigned long long issue;
	union {
		unsigned long long xdp_pass;
		unsigned long long info;
	};
	unsigned long long xdp_drop;
	unsigned long long xdp_redirect;
} __attribute__((aligned(64)));

#endif
