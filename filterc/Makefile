# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
TOOL_NAME := filterc
USER_TARGETS := filterc

EXTRA_BUILD := bpfc.o
USER_GEN := $(EXTRA_BUILD)
EXTRA_USER_DEPS := $(USER_GEN)

LIB_DIR = ../lib
USER_LIBS = $(EXTRA_BUILD) -lpcap

include $(LIB_DIR)/common.mk

$(EXTRA_BUILD): %.o: %.c %.h
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) -c $< -o $@
