# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS := test_xsk_refcnt test_xdp_frags test_link_detach test_xsk_umem_flags
STATIC_LINK_TARGETS := check_kern_compat test_dispatcher_versions
BPF_TARGETS := xdp_dispatcher_v1 xdp_pass
USER_LIBS := -lpthread
USER_EXTRA_C := test_utils.c

EXTRA_DEPS += xdp_dispatcher_v1.h
EXTRA_USER_DEPS += test_utils.h $(USER_EXTRA_C)

TEST_FILE := ./test-libxdp.sh
TEST_RUNNER := ./test_runner.sh

LIB_DIR := ../..
LDLIBS += $(USER_LIBS)

include $(LIB_DIR)/libxdp/libxdp.mk
include $(LIB_DIR)/defines.mk

ifeq ($(HAVE_CAP_NG),y)
	USER_TARGETS += test_xsk_non_privileged
	CFLAGS += $(CAP_NG_CFLAGS)
	LDLIBS += $(CAP_NG_LDLIBS)
endif

USER_C := ${USER_TARGETS:=.c} ${STATIC_LINK_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}
BPF_OBJS := $(BPF_TARGETS:=.o)

LDFLAGS+=-L$(LIBXDP_DIR)
STATIC_OBJECT_LIBXDP:=$(LIBXDP_DIR)/libxdp.a
STATIC_LDLIBS:=-l:libxdp.a $(LDLIBS)
ifeq ($(DYNAMIC_LIBXDP),1)
	LDLIBS:=-lxdp $(LDLIBS)
	OBJECT_LIBXDP:=$(LIBXDP_DIR)/libxdp.so.$(LIBXDP_VERSION)
else
	LDLIBS:=$(STATIC_LDLIBS)
	OBJECT_LIBXDP:=$(STATIC_OBJECT_LIBXDP)
endif

# Detect submodule libbpf source file changes
ifeq ($(SYSTEM_LIBBPF),n)
	LIBBPF_SOURCES := $(wildcard $(LIBBPF_DIR)/src/*.[ch])
endif

LIBXDP_SOURCES := $(wildcard $(LIBXDP_DIR)/*.[ch] $(LIBXDP_DIR)/*.in)

CFLAGS += -I$(HEADER_DIR)

BPF_HEADERS := $(wildcard $(HEADER_DIR)/bpf/*.h) $(wildcard $(HEADER_DIR)/xdp/*.h)

all: $(USER_TARGETS) $(STATIC_LINK_TARGETS) $(BPF_OBJS)

.PHONY: clean
clean::
	$(Q)rm -f $(USER_TARGETS) $(USER_OBJ)

.PHONY: install
install: all
	install -m 0755 -d $(DESTDIR)$(SCRIPTSDIR)/tests/libxdp
	install -m 0644 $(TEST_FILE) $(DESTDIR)$(SCRIPTSDIR)/tests/libxdp
	install -m 0755 $(USER_TARGETS) $(STATIC_LINK_TARGETS) $(DESTDIR)$(SCRIPTSDIR)/tests/libxdp
	install -m 0644 $(BPF_OBJS) $(DESTDIR)$(SCRIPTSDIR)/tests/libxdp

$(OBJECT_LIBBPF): $(LIBBPF_SOURCES)
	$(Q)$(MAKE) -C $(LIB_DIR) libbpf

$(OBJECT_LIBXDP): $(LIBXDP_SOURCES)
	$(Q)$(MAKE) -C $(LIBXDP_DIR)

# Create expansions for dependencies
LIB_H := ${LIB_OBJS:.o=.h}

# Detect if any of common obj changed and create dependency on .h-files
$(LIB_OBJS): %.o: %.c %.h $(LIB_H)
	$(Q)$(MAKE) -C $(dir $@) $(notdir $@)

$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) $(LIBMK) $(LIB_OBJS) $(EXTRA_DEPS) $(EXTRA_USER_DEPS)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) \
	 $< $(USER_EXTRA_C) $(LDLIBS)

$(STATIC_LINK_TARGETS): %: %.c  $(OBJECT_LIBBPF) $(STATIC_OBJECT_LIBXDP) $(LIBMK) $(LIB_OBJS) $(EXTRA_DEPS) $(EXTRA_USER_DEPS)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) \
	 $< $(USER_EXTRA_C) $(STATIC_LDLIBS)

$(BPF_OBJS): %.o: %.c $(BPF_HEADERS) $(LIBMK) $(EXTRA_DEPS)
	$(QUIET_CLANG)$(CLANG) -target $(BPF_TARGET) $(BPF_CFLAGS) -O2 -c -g -o $@ $<

run: all
	$(Q)env CC="$(CC)" CFLAGS="$(CFLAGS) $(LDFLAGS)" CPPFLAGS="$(CPPFLAGS)" LDLIBS="$(LDLIBS)" V=$(V) $(TEST_RUNNER) $(TEST_FILE) $(RUN_TESTS)
