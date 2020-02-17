# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS := xdp-loader
XDP_TARGETS := xdp-dispatcher

LIB_DIR = ../lib

NUM_CHAIN_PROGS ?= 10

include $(LIB_DIR)/common.mk

xdp-dispatcher.c: xdp-dispatcher.c.in Makefile
	$(QUIET_M4)m4 -DNUM_PROGS=$(NUM_CHAIN_PROGS) $< > $@


