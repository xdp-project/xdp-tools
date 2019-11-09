# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_filt_black_udp xdp_filt_black_tcp xdp_filt_black_ip \
	xdp_filt_black_ethernet xdp_filt_black_all \
	xdp_filt_white_udp xdp_filt_white_tcp xdp_filt_white_ip \
	xdp_filt_white_ethernet xdp_filt_white_all

USER_TARGETS := xdp-filter
EXTRA_DEPS := xdp_filt_prog.h

EXTRA_USER_DEPS := prog_features.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

prog_features.h: ${XDP_TARGETS:=.o} extract_features.sh
	$(Q)sh extract_features.sh $^ > prog_features.h

