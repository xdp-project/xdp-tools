# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LIB_DIR = ..

include libxdp.mk
include $(LIB_DIR)/defines.mk
include $(LIB_DIR)/util/util.mk

OBJDIR ?= .
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := libxdp.o
XDP_OBJS := xdp-dispatcher.o
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
STATIC_LIBS := $(OBJDIR)/libxdp.a

SHARED_CFLAGS += -fPIC -DSHARED
LIB_HEADERS := $(wildcard $(HEADER_DIR)/xdp/*.h)
BPF_HEADERS := $(wildcard $(HEADER_DIR)/bpf/*.h) $(wildcard $(HEADER_DIR)/xdp/*.h)
EXTRA_LIB_DEPS := $(OBJECT_LIBBPF) $(LIBMK) $(LIB_OBJS) $(LIB_HEADERS)
PC_FILE := $(OBJDIR)/libxdp.pc

CFLAGS += -I$(HEADER_DIR) -I$(LIB_DIR)/util
BPF_CFLAGS += -I$(HEADER_DIR)


ifndef BUILD_STATIC_ONLY
	SHARED_LIBS := $(OBJDIR)/libxdp.so \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	VERSION_SCRIPT := libxdp.map
endif

all: $(STATIC_LIBS) $(SHARED_LIBS) $(XDP_OBJS) $(PC_FILE)

clean:
	$(Q)rm -f $(STATIC_LIBS) $(STATIC_OBJS) $(SHARED_LIBS) $(SHARED_OBJS) $(XDP_OBJS) $(PC_FILE)
	$(Q)for d in $(SHARED_OBJDIR) $(STATIC_OBJDIR); do \
		[ -d "$$d" ] && rmdir "$$d"; done || true

install: all
	$(Q)install -d -m 0755 $(DESTDIR)$(HDRDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q)install -d -m 0755 $(DESTDIR)$(BPF_OBJECT_DIR)
	$(Q)install -m 0644 $(LIB_HEADERS) $(DESTDIR)$(HDRDIR)/
	$(Q)install -m 0644 $(PC_FILE) $(DESTDIR)$(libdir)/pkgconfig/
	$(Q)install -m 0755 $(SHARED_LIBS) $(STATIC_LIBS) $(DESTDIR)$(LIBDIR)
	$(Q)install -m 0755 $(XDP_OBJS) $(DESTDIR)$(BPF_OBJECT_DIR)


$(OBJDIR)/libxdp.a: $(STATIC_OBJS)
	$(QUIET_LINK)$(AR) rcs $@ $^

$(OBJDIR)/libxdp.so: $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION): $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libxdp.so.$(LIBXDP_VERSION): $(SHARED_OBJS)
	$(QUIET_LINK)$(CC) -shared -Wl,-soname,libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		      -Wl,--version-script=$(VERSION_SCRIPT) \
		      $^ $(ALL_LDFLAGS) -o $@

$(OBJDIR)/libxdp.pc:
	$(Q)sed -e "s|@PREFIX@|$(PREFIX)|" \
			-e "s|@LIBDIR@|$(LIBDIR)|" \
			-e "s|@VERSION@|$(LIBXDP_VERSION)|" \
			< libxdp.pc.template > $@

$(STATIC_OBJDIR):
	$(Q)mkdir -p $(STATIC_OBJDIR)

$(SHARED_OBJDIR):
	$(Q)mkdir -p $(SHARED_OBJDIR)

$(STATIC_OBJDIR)/%.o: %.c $(EXTRA_LIB_DEPS) | $(STATIC_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS)  -Wall -I../../headers -c $< -o $@

$(SHARED_OBJDIR)/%.o: %.c $(EXTRA_LIB_DEPS) | $(SHARED_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(SHARED_CFLAGS) -Wall -I../../headers -c $< -o $@


xdp-dispatcher.c: xdp-dispatcher.c.in Makefile
	$(QUIET_M4)m4 $(DEFINES) $< > $@

$(XDP_OBJS): %.o: %.c $(BPF_HEADERS) $(LIBMK)
	$(QUIET_CLANG)$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
