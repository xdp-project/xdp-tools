include util.mk

LIB_DIR ?= ..

include $(LIB_DIR)/defines.mk
include $(LIBXDP_DIR)/libxdp.mk

all: $(UTIL_OBJS)

UTIL_SKEL_H = $(UTIL_BPF_OBJS:.bpf.o=.skel.h)

$(UTIL_OBJS): %.o: %.c %.h $(UTIL_SKEL_H) $(LIBMK)
	$(QUIET_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -Wall -I../../headers -c -o $@ $<

clean:
	$(Q)rm -f $(UTIL_OBJS) $(UTIL_BPF_OBJS) $(UTIL_SKEL_H) *.ll

BPF_CFLAGS += -I$(HEADER_DIR) $(ARCH_INCLUDES)

$(UTIL_BPF_OBJS): %.o: %.c $(KERN_USER_H) $(BPF_HEADERS) $(LIBMK)
	$(QUIET_CLANG)$(CLANG) -target $(BPF_TARGET) $(BPF_CFLAGS) -O2 -c -g -o $@ $<

$(UTIL_SKEL_H): %.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< name ${@:.skel.h=} > $@
