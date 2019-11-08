
include $(LIB_DIR)/../config.mk

PREFIX?=/usr
LIBDIR?=$(PREFIX)/lib
SBINDIR?=$(PREFIX)/sbin
BPF_DIR_MNT ?=/sys/fs/bpf
BPF_OBJECT_DIR ?=$(LIBDIR)/bpf

DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" -DBPF_OBJECT_PATH=\"$(BPF_OBJECT_DIR)\"

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

CFLAGS += $(DEFINES)
BPF_CFLAGS += $(DEFINES)

MAKEFILES := Makefile $(LIB_DIR)/../config.mk $(LIB_DIR)/defines.mk $(LIB_DIR)/common.mk

