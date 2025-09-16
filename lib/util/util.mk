LIB_DIR ?= ..
include $(LIB_DIR)/defines.mk

UTIL_OBJS := params.o logging.o util.o stats.o xpcapng.o
UTIL_BPF_OBJS :=

ifneq ($(BPFTOOL),)
UTIL_OBJS += xdp_sample.o xdpsock.o
UTIL_BPF_OBJS += xdp_sample.bpf.o xdp_load_bytes.bpf.o xdpsock.bpf.o
endif

