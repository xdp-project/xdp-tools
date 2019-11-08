
include $(LIB_DIR)/../config.mk

BPF_DIR_MNT ?=/sys/fs/bpf
BPF_OBJECT_PATH ?=/usr/lib/bpf

DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" -DBPF_OBJECT_PATH=\"$(BPF_OBJECT_PATH)\"

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

CFLAGS += $(DEFINES)

MAKEFILES := Makefile $(LIB_DIR)/../config.mk $(LIB_DIR)/defines.mk $(LIB_DIR)/common.mk

