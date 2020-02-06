# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

EXTRA_TARGETS := libxdp.so libxdp.a
LIB_DIR = ..
LIBXDP_MAJOR_VERSION := 0
LIBXDP_VERSION := 0.0.1

include $(LIB_DIR)/common.mk

OBJDIR ?= .
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := libxdp.o
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
STATIC_LIBS := $(OBJDIR)/libxdp.a

SHARED_CFLAGS += -fPIC -fvisibility=hidden -DSHARED
EXTRA_LIB_DEPS := $(OBJECT_LIBBPF) $(LIBMK) $(LIB_OBJS)

ifndef BUILD_STATIC_ONLY
	SHARED_LIBS := $(OBJDIR)/libxdp.so \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	VERSION_SCRIPT := libxdp.map
endif

clean::
	$(Q)rm -f $(STATIC_LIBS) $(STATIC_OBJS) $(SHARED_LIBS) $(SHARED_OBJS)
	$(Q)for d in $(SHARED_OBJDIR) $(STATIC_OBJDIR); do \
		[ -d "$$d" ] && rmdir "$$d"; done || true


$(OBJDIR)/libxdp.a: $(STATIC_OBJS)
	$(AR) rcs $@ $^

$(OBJDIR)/libxdp.so: $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION)
	ln -sf $(^F) $@

$(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION): $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	ln -sf $(^F) $@

$(OBJDIR)/libxdp.so.$(LIBXDP_VERSION): $(SHARED_OBJS)
	$(QUIET_CC)$(CC) -shared -Wl,-soname,libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		      $^ $(ALL_LDFLAGS) -o $@


$(STATIC_OBJDIR):
	mkdir -p $(STATIC_OBJDIR)

$(SHARED_OBJDIR):
	mkdir -p $(SHARED_OBJDIR)

$(STATIC_OBJDIR)/%.o: %.c $(EXTRA_LIB_DEPS) | $(STATIC_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS)  -Wall -I../../headers -c $< -o $@

$(SHARED_OBJDIR)/%.o: %.c $(EXTRA_LIB_DEPS) | $(SHARED_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(SHARED_CFLAGS) -Wall -I../../headers -c $< -o $@


