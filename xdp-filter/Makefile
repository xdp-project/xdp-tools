# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_filt_udp xdp_filt_tcp xdp_filt_ip xdp_filt_ethernet xdp_filt_all
USER_TARGETS := xdp-filter
EXTRA_DEPS := xdp_filt_prog.h

EXTRA_USER_DEPS := prog_features.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

prog_features.h: ${XDP_TARGETS:=.o} extract_features.sh
	sh extract_features.sh $^ > prog_features.h

