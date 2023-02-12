# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_redirect_basic.bpf xdp_redirect_cpumap.bpf xdp_redirect_devmap.bpf \
	       xdp_redirect_devmap_multi.bpf xdp_basic.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

# Don't install skeleton object files
XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-bench
MAN_PAGE := xdp-bench.8
TEST_FILE := tests/test-xdp-bench.sh
USER_TARGETS := xdp-bench
USER_EXTRA_C := xdp_redirect_basic.c xdp_redirect_cpumap.c xdp_redirect_devmap.c \
		xdp_redirect_devmap_multi.c xdp_basic.c
EXTRA_USER_DEPS := xdp-bench.h

LIB_DIR       = ../lib

include $(LIB_DIR)/common.mk

