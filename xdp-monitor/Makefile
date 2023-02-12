# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_monitor.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

# Don't install skeleton object files
XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-monitor
MAN_PAGE := xdp-monitor.8
TEST_FILE := tests/test-xdp-monitor.sh
USER_TARGETS := xdp-monitor
LIB_DIR       = ../lib

include $(LIB_DIR)/common.mk

