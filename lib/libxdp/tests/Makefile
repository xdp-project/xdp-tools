# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS := test_xsk_refcnt
USER_LIBS := -lpthread

EXTRA_DEPS +=
EXTRA_USER_DEPS += test_utils.h

TEST_FILE := ./test-libxdp.sh
TEST_RUNNER := ./test_runner.sh

USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

LIB_DIR := ../..
LDLIBS += $(USER_LIBS)

include $(LIB_DIR)/defines.mk

LDFLAGS+=-L$(LIBXDP_DIR)
ifeq ($(DYNAMIC_LIBXDP),1)
	LDLIBS:=-lxdp $(LDLIBS)
	OBJECT_LIBXDP:=$(LIBXDP_DIR)/libxdp.so.$(LIBXDP_VERSION)
else
	LDLIBS:=-l:libxdp.a $(LDLIBS)
	OBJECT_LIBXDP:=$(LIBXDP_DIR)/libxdp.a
endif

# Detect submodule libbpf source file changes
ifeq ($(SYSTEM_LIBBPF),n)
	LIBBPF_SOURCES := $(wildcard $(LIBBPF_DIR)/src/*.[ch])
endif

LIBXDP_SOURCES := $(wildcard $(LIBXDP_DIR)/*.[ch] $(LIBXDP_DIR)/*.in)

CFLAGS += -I$(HEADER_DIR)

BPF_HEADERS := $(wildcard $(HEADER_DIR)/bpf/*.h) $(wildcard $(HEADER_DIR)/xdp/*.h)

all: $(USER_TARGETS)

.PHONY: clean
clean::
	$(Q)rm -f $(USER_TARGETS) $(USER_OBJ)

$(OBJECT_LIBBPF): $(LIBBPF_SOURCES)
	$(Q)$(MAKE) -C $(LIB_DIR) libbpf

$(OBJECT_LIBXDP): $(LIBXDP_SOURCES)
	$(Q)$(MAKE) -C $(LIBXDP_DIR)

# Create expansions for dependencies
LIB_H := ${LIB_OBJS:.o=.h}

# Detect if any of common obj changed and create dependency on .h-files
$(LIB_OBJS): %.o: %.c %.h $(LIB_H)
	$(Q)$(MAKE) -C $(dir $@) $(notdir $@)

ALL_EXEC_TARGETS=$(USER_TARGETS)
$(ALL_EXEC_TARGETS): %: %.c  $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) $(LIBMK) $(LIB_OBJS) $(EXTRA_DEPS) $(EXTRA_USER_DEPS)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) \
	 $< $(LDLIBS)

run: all
	$(Q)env CC="$(CC)" CFLAGS="$(CFLAGS) $(LDFLAGS)" CPPFLAGS="$(CPPFLAGS)" LDLIBS="$(LDLIBS)" V=$(V) $(TEST_RUNNER) $(TEST_FILE)
