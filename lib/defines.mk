CFLAGS ?= -O2 -g
BPF_CFLAGS ?= -Wno-visibility -fno-stack-protector
BPF_TARGET ?= bpf

HAVE_FEATURES :=

include $(LIB_DIR)/../config.mk
include $(LIB_DIR)/../version.mk

PREFIX?=/usr/local
LIBDIR?=$(PREFIX)/lib
SBINDIR?=$(PREFIX)/sbin
HDRDIR?=$(PREFIX)/include/xdp
DATADIR?=$(PREFIX)/share
RUNDIR?=/run
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
	-DMAX_DISPATCHER_ACTIONS=$(MAX_DISPATCHER_ACTIONS) -DTOOLS_VERSION=\"$(TOOLS_VERSION)\" \
	-DLIBBPF_VERSION=\"$(LIBBPF_VERSION)\" -DRUNDIR=\"$(RUNDIR)\"

DEFINES += $(foreach feat,$(HAVE_FEATURES),-DHAVE_$(feat))

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

ifeq ($(SYSTEM_LIBBPF),y)
DEFINES += -DLIBBPF_DYNAMIC
endif

DEFINES += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS += -std=gnu11 -Wextra -Werror $(DEFINES) $(ARCH_INCLUDES)
BPF_CFLAGS += $(DEFINES) $(filter -ffile-prefix-map=%,$(CFLAGS)) $(ARCH_INCLUDES)

CONFIGMK := $(LIB_DIR)/../config.mk
LIBMK := Makefile $(CONFIGMK) $(LIB_DIR)/defines.mk $(LIB_DIR)/common.mk $(LIB_DIR)/../version.mk
