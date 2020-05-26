CFLAGS ?= -O2 -g
BPF_CFLAGS ?= -Wno-visibility

include $(LIB_DIR)/../config.mk

PREFIX?=/usr/local
LIBDIR?=$(PREFIX)/lib
SBINDIR?=$(PREFIX)/sbin
HDRDIR?=$(PREFIX)/include/xdp
DATADIR?=$(PREFIX)/share
MANDIR?=$(DATADIR)/man
BPF_DIR_MNT ?=/sys/fs/bpf
BPF_OBJECT_DIR ?=$(LIBDIR)/bpf
MAX_DISPATCHER_ACTIONS ?=10

HEADER_DIR = $(LIB_DIR)/../headers
TEST_DIR = $(LIB_DIR)/testing
LIBXDP_DIR := $(LIB_DIR)/libxdp
LIBBPF_DIR := $(LIB_DIR)/libbpf
DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" -DBPF_OBJECT_PATH=\"$(BPF_OBJECT_DIR)\" \
	-DMAX_DISPATCHER_ACTIONS=$(MAX_DISPATCHER_ACTIONS)

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

CFLAGS += -Werror $(DEFINES)
BPF_CFLAGS += $(DEFINES)

CONFIGMK := $(LIB_DIR)/../config.mk
LIBMK := Makefile $(CONFIGMK) $(LIB_DIR)/defines.mk $(LIB_DIR)/common.mk

