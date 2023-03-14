# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
TOOL_NAME := filterc
USER_TARGETS := filterc
# Just needed for tests
XDP_TARGETS := tests/wrapper_prog
TEST_TARGETS := tests/test_bpfc
TEST_FILE := tests/test-filterc.sh

EXTRA_BUILD := bpfc.o
USER_GEN := $(EXTRA_BUILD)
EXTRA_USER_DEPS := $(USER_GEN)

LIB_DIR = ../lib
USER_LIBS = $(EXTRA_BUILD) -lpcap -lelf

include $(LIB_DIR)/common.mk

$(EXTRA_BUILD): %.o: %.c %.h
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) -c $< -o $@
