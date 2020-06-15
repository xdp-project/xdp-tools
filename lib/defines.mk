CFLAGS ?= -O2 -g
BPF_CFLAGS ?= -Wno-visibility

include $(LIB_DIR)/../config.mk
include $(LIB_DIR)/../version.mk

PREFIX?=/usr/local
LIBDIR?=$(PREFIX)/lib
SBINDIR?=$(PREFIX)/sbin
HDRDIR?=$(PREFIX)/include/xdp
DATADIR?=$(PREFIX)/share
MANDIR?=$(DATADIR)/man
SCRIPTSDIR?=$(DATADIR)/xdp-tools
BPF_DIR_MNT ?=/sys/fs/bpf
BPF_OBJECT_DIR ?=$(LIBDIR)/bpf
MAX_DISPATCHER_ACTIONS ?=10

HEADER_DIR = $(LIB_DIR)/../headers
TEST_DIR = $(LIB_DIR)/testing
LIBXDP_DIR := $(LIB_DIR)/libxdp
LIBBPF_DIR := $(LIB_DIR)/libbpf

DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" -DBPF_OBJECT_PATH=\"$(BPF_OBJECT_DIR)\" \
	-DMAX_DISPATCHER_ACTIONS=$(MAX_DISPATCHER_ACTIONS) -DTOOLS_VERSION=\"$(TOOLS_VERSION)\"

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

ifeq ($(HAVE_LIBBPF_PERF_BUFFER__CONSUME),y)
DEFINES +=-DHAVE_LIBBPF_PERF_BUFFER__CONSUME
endif

CFLAGS += -Werror $(DEFINES)
BPF_CFLAGS += $(DEFINES)

CONFIGMK := $(LIB_DIR)/../config.mk
LIBMK := Makefile $(CONFIGMK) $(LIB_DIR)/defines.mk $(LIB_DIR)/common.mk $(LIB_DIR)/../version.mk

