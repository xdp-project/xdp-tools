# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  LIB_DIR = ../lib/
#  include $(LIB_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
BPF_SKEL_OBJ = ${BPF_SKEL_TARGETS:=.o}
BPF_SKEL_H = ${BPF_SKEL_OBJ:.bpf.o=.skel.h}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}
TEST_C := ${TEST_TARGETS:=.c}
TEST_OBJ := ${TEST_C:.c=.o}
XDP_OBJ_INSTALL ?= $(XDP_OBJ)
MAN_FILES := $(MAN_PAGE)

# Expect this is defined by including Makefile, but define if not
LIB_DIR ?= ../lib
LDLIBS ?= $(USER_LIBS)
LDLIBS += -lm

include $(LIB_DIR)/defines.mk
include $(LIB_DIR)/libxdp/libxdp.mk

# get list of objects in util
include $(LIB_DIR)/util/util.mk

# Extend if including Makefile already added some
LIB_OBJS += $(foreach obj,$(UTIL_OBJS),$(LIB_DIR)/util/$(obj))

EXTRA_DEPS +=
EXTRA_USER_DEPS +=

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

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS += -I$(HEADER_DIR) -I$(LIB_DIR)/util $(ARCH_INCLUDES)
BPF_CFLAGS += -I$(HEADER_DIR) $(ARCH_INCLUDES)

BPF_HEADERS := $(wildcard $(HEADER_DIR)/bpf/*.h) $(wildcard $(HEADER_DIR)/xdp/*.h)

all: $(USER_TARGETS) $(XDP_OBJ) $(EXTRA_TARGETS) $(TEST_TARGETS) man

.PHONY: clean
clean::
	$(Q)rm -f $(USER_TARGETS) $(XDP_OBJ) $(TEST_TARGETS) $(USER_OBJ) $(TEST_OBJ) $(USER_GEN) $(BPF_SKEL_H) *.ll

.PHONY: install
install: all install_local
	install -m 0755 -d $(DESTDIR)$(SBINDIR)
	install -m 0755 -d $(DESTDIR)$(BPF_OBJECT_DIR)
	$(if $(USER_TARGETS),install -m 0755 $(USER_TARGETS) $(DESTDIR)$(SBINDIR))
	$(if $(XDP_OBJ_INSTALL),install -m 0644 $(XDP_OBJ_INSTALL) $(DESTDIR)$(BPF_OBJECT_DIR))
	$(if $(MAN_FILES),install -m 0755 -d $(DESTDIR)$(MANDIR)/man8)
	$(if $(MAN_FILES),install -m 0644 $(MAN_FILES) $(DESTDIR)$(MANDIR)/man8)
	$(if $(SCRIPTS_FILES),install -m 0755 -d $(DESTDIR)$(SCRIPTSDIR))
	$(if $(SCRIPTS_FILES),install -m 0755 $(SCRIPTS_FILES) $(DESTDIR)$(SCRIPTSDIR))
	$(if $(TEST_FILE),install -m 0755 -d $(DESTDIR)$(SCRIPTSDIR)/tests/$(TOOL_NAME))
	$(if $(TEST_FILE),install -m 0644 $(TEST_FILE) $(DESTDIR)$(SCRIPTSDIR)/tests/$(TOOL_NAME))
	$(if $(TEST_FILE_DEPS),install -m 0644 $(TEST_FILE_DEPS) $(DESTDIR)$(SCRIPTSDIR)/tests/$(TOOL_NAME))
	$(if $(TEST_TARGETS),install -m 0755 $(TEST_TARGETS) $(DESTDIR)$(SCRIPTSDIR))

.PHONY: install_local
install_local::

$(OBJECT_LIBBPF): $(LIBBPF_SOURCES)
	$(Q)$(MAKE) -C $(LIB_DIR) libbpf

$(OBJECT_LIBXDP): $(LIBXDP_SOURCES)
	$(Q)$(MAKE) -C $(LIBXDP_DIR)

$(CONFIGMK):
	$(Q)$(MAKE) -C $(LIB_DIR)/.. config.mk

# Create expansions for dependencies
LIB_H := ${LIB_OBJS:.o=.h}

# Detect if any of common obj changed and create dependency on .h-files
$(LIB_OBJS): %.o: %.c %.h $(LIB_H)
	$(Q)$(MAKE) -C $(dir $@) $(notdir $@)

ALL_EXEC_TARGETS=$(USER_TARGETS) $(TEST_TARGETS)
$(ALL_EXEC_TARGETS): %: %.c  $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) $(LIBMK) $(LIB_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) $(EXTRA_USER_DEPS) $(BPF_SKEL_H) $(USER_EXTRA_C)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) \
	 $< $(USER_EXTRA_C) $(LDLIBS)

$(XDP_OBJ): %.o: %.c $(KERN_USER_H) $(EXTRA_DEPS) $(BPF_HEADERS) $(LIBMK)
	$(QUIET_CLANG)$(CLANG) -S \
	    -target $(BPF_TARGET) \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)$(LLC) -march=$(BPF_TARGET) -filetype=obj -o $@ ${@:.o=.ll}

$(BPF_SKEL_H): %.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< name ${@:.skel.h=} > $@

.PHONY: man
ifeq ($(EMACS),)
man: ;
else
man: $(MAN_PAGE)
$(MAN_PAGE): README.org $(LIBMK) $(LIB_DIR)/export-man.el
	$(QUIET_GEN)$(EMACS) -Q --batch --load "$(LIB_DIR)/export-man.el" \
		--eval "(export-man-page \"$@\" \"$<\" \"$(HAVE_FEATURES)\" \"v$(TOOLS_VERSION)\")"
endif

.PHONY: test
ifeq ($(TEST_FILE),)
test:
	@echo "    No tests defined"
else
test: all
	$(Q)$(TEST_DIR)/test_runner.sh $(TEST_FILE)
endif
