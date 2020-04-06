# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

EXTRA_TARGETS := libxdp.so libxdp.a
XDP_TARGETS := xdp-dispatcher

LIB_DIR = ..

include libxdp.mk
include $(LIB_DIR)/defines.mk
include $(LIB_DIR)/util/util.mk

OBJDIR ?= .
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := libxdp.o
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
STATIC_LIBS := $(OBJDIR)/libxdp.a

SHARED_CFLAGS += -fPIC -DSHARED
LIB_HEADERS := $(wildcard ../../headers/xdp/*.h)
EXTRA_LIB_DEPS := $(OBJECT_LIBBPF) $(LIBMK) $(LIB_OBJS) $(LIB_HEADERS)

CFLAGS += -I$(HEADER_DIR) -I$(LIB_DIR)/util
BPF_CFLAGS += -I$(HEADER_DIR)

ifndef BUILD_STATIC_ONLY
	SHARED_LIBS := $(OBJDIR)/libxdp.so \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	VERSION_SCRIPT := libxdp.map
endif

all: $(STATIC_LIBS) $(SHARED_LIBS)

clean:
	$(Q)rm -f $(STATIC_LIBS) $(STATIC_OBJS) $(SHARED_LIBS) $(SHARED_OBJS)
	$(Q)for d in $(SHARED_OBJDIR) $(STATIC_OBJDIR); do \
		[ -d "$$d" ] && rmdir "$$d"; done || true

install:
	$(Q)install -d -m 0755 $(DESTDIR)$(HDRDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)
	$(Q)install -m 0644 $(LIB_HEADERS) $(DESTDIR)$(HDRDIR)/
	$(Q)install -m 0755 $(SHARED_LIBS) $(STATIC_LIBS) $(DESTDIR)$(LIBDIR)


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
