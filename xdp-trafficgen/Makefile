# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_trafficgen.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

# Don't install skeleton object files
XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-trafficgen
USER_TARGETS := xdp-trafficgen
MAN_PAGE := xdp-trafficgen.8
EXTRA_DEPS := xdp-trafficgen.h
USER_LIBS     = -lpthread
TEST_FILE := tests/test-xdp-trafficgen.sh

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

