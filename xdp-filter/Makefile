# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdpfilt_blk_udp xdpfilt_blk_tcp xdpfilt_blk_ip \
	xdpfilt_blk_eth xdpfilt_blk_all \
	xdpfilt_wht_udp xdpfilt_wht_tcp xdpfilt_wht_ip \
	xdpfilt_wht_eth xdpfilt_wht_all

USER_TARGETS := xdp-filter
EXTRA_DEPS := xdpfilt_prog.h
MAN_PAGE := xdp-filter.8

EXTRA_USER_DEPS := prog_features.h

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

prog_features.h: ${XDP_TARGETS:=.o} extract_features.sh
	$(Q)sh extract_features.sh $^ > prog_features.h

