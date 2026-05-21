# SPDX-License-Identifier: GPL-2.0

ifdef VLANS_PATCHED
CFLAGS += -DVLANS_PATCHED
BPF_CFLAGS += -DVLANS_PATCHED
endif

ifdef VLANS_USERSPACE
CFLAGS += -DVLANS_USERSPACE
BPF_CFLAGS += -DVLANS_USERSPACE
endif

XDP_TARGETS := xdp_forward.bpf xdp_flowtable.bpf xdp_flowtable_sample.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-forward
MAN_PAGE := xdp-forward.8
TEST_FILE := tests/test-xdp-forward.sh
USER_TARGETS := xdp-forward

LIB_DIR := ../lib

include $(LIB_DIR)/common.mk
