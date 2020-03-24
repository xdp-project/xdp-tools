# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdpdump_bpf
USER_TARGETS := xdpdump

LIB_DIR   = ../lib
USER_LIBS = -lpcap
USER_CFLAGS = -DXDPDUMP_VERSION=\"$(LIBXDP_VERSION)\"

include $(LIB_DIR)/common.mk
