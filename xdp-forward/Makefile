# SPDX-License-Identifier: GPL-2.0

XDP_TARGETS := xdp_forward.bpf xdp_flowtable.bpf xdp_flowtable_sample.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-forward
MAN_PAGE := xdp-forward.8
TEST_FILE := tests/test-xdp-forward.sh
USER_TARGETS := xdp-forward
USER_EXTRA_C := xdp-userspace-vlans.c
EXTRA_USER_DEPS := xdp-userspace-vlans.h xdp_forward_vlan.h
EXTRA_DEPS := xdp_forward_vlan.h

LIB_DIR := ../lib

include $(LIB_DIR)/common.mk
