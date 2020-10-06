# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdpfilt_dny_udp xdpfilt_dny_tcp xdpfilt_dny_ip \
	xdpfilt_dny_eth xdpfilt_dny_all \
	xdpfilt_alw_udp xdpfilt_alw_tcp xdpfilt_alw_ip \
	xdpfilt_alw_eth xdpfilt_alw_all

TOOL_NAME := xdp-filter
USER_TARGETS := xdp-filter
EXTRA_DEPS := xdpfilt_prog.h
MAN_PAGE := xdp-filter.8
TEST_FILE := tests/test-xdp-filter.sh
TEST_FILE_DEPS := $(wildcard tests/*.py)

USER_GEN := prog_features.h
EXTRA_USER_DEPS := $(USER_GEN)

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

prog_features.h: ${XDP_TARGETS:=.o} extract_features.sh
	$(Q)sh extract_features.sh $^ > $@ || ( ret=$$?; rm -f $@; exit $$ret )

