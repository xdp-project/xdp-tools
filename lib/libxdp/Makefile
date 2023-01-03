# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LIB_DIR = ..

include libxdp.mk
include $(LIB_DIR)/defines.mk

OBJDIR ?= .
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := libxdp.o xsk.o
XDP_OBJS := xdp-dispatcher.o xsk_def_xdp_prog.o xsk_def_xdp_prog_5.3.o
EMBEDDED_XDP_OBJS := $(addsuffix .embed.o,$(basename $(XDP_OBJS)))
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS)) $(EMBEDDED_XDP_OBJS)
STATIC_LIBS := $(OBJDIR)/libxdp.a
MAN_PAGE := libxdp.3
MAN_OBJ := ${MAN_PAGE:.3=.man}
MAN_FILES := $(MAN_PAGE)
TEST_DIR := tests

SHARED_CFLAGS += -fPIC -DSHARED
LIB_HEADERS := $(wildcard $(HEADER_DIR)/xdp/*.h)
BPF_HEADERS := $(wildcard $(HEADER_DIR)/bpf/*.h) $(wildcard $(HEADER_DIR)/xdp/*.h)
EXTRA_LIB_DEPS := $(OBJECT_LIBBPF) $(LIBMK) $(LIB_OBJS) $(LIB_HEADERS) compat.h libxdp_internal.h xsk_def_xdp_prog.h bpf_instr.h
PC_FILE := $(OBJDIR)/libxdp.pc
TEMPLATED_SOURCES := xdp-dispatcher.c

CFLAGS += -I$(HEADER_DIR)
BPF_CFLAGS += -I$(HEADER_DIR)


ifndef BUILD_STATIC_ONLY
SHARED_LIBS := $(OBJDIR)/libxdp.so \
	       $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION) \
	       $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
VERSION_SCRIPT := libxdp.map
CHECK_RULES := check_abi
endif

all: $(STATIC_LIBS) $(SHARED_LIBS) $(XDP_OBJS) $(PC_FILE) check man

clean:
	$(Q)rm -f $(STATIC_LIBS) $(STATIC_OBJS) $(SHARED_LIBS) $(SHARED_OBJS) $(XDP_OBJS) $(PC_FILE) $(MAN_OBJ) $(TEMPLATED_SOURCES)
	$(Q)for d in $(SHARED_OBJDIR) $(STATIC_OBJDIR); do \
		[ -d "$$d" ] && rmdir "$$d"; done || true
	$(Q)$(MAKE) -C $(TEST_DIR) clean

install: all
	$(Q)install -d -m 0755 $(DESTDIR)$(HDRDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)
	$(Q)install -d -m 0755 $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q)install -d -m 0755 $(DESTDIR)$(BPF_OBJECT_DIR)
	$(Q)install -m 0644 $(LIB_HEADERS) $(DESTDIR)$(HDRDIR)/
	$(Q)install -m 0644 $(PC_FILE) $(DESTDIR)$(LIBDIR)/pkgconfig/
	$(Q)cp -fpR $(SHARED_LIBS) $(STATIC_LIBS) $(DESTDIR)$(LIBDIR)
	$(Q)install -m 0755 $(XDP_OBJS) $(DESTDIR)$(BPF_OBJECT_DIR)
	$(if $(MAN_FILES),$(Q)install -m 0755 -d $(DESTDIR)$(MANDIR)/man3)
	$(if $(MAN_FILES),$(Q)install -m 0644 $(MAN_FILES) $(DESTDIR)$(MANDIR)/man3)


$(OBJDIR)/libxdp.a: $(STATIC_OBJS)
	$(QUIET_LINK)$(AR) rcs $@ $^

$(OBJDIR)/libxdp.so: $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION): $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libxdp.so.$(LIBXDP_VERSION): $(SHARED_OBJS)
	$(QUIET_LINK)$(CC) -shared -Wl,-soname,libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		      -Wl,--version-script=$(VERSION_SCRIPT) \
		      $^ $(LDFLAGS) $(LDLIBS) -o $@

$(OBJDIR)/libxdp.pc:
	$(Q)sed -e "s|@PREFIX@|$(PREFIX)|" \
			-e "s|@LIBDIR@|$(LIBDIR)|" \
			-e "s|@VERSION@|$(TOOLS_VERSION)|" \
			< libxdp.pc.template > $@

$(STATIC_OBJDIR):
	$(Q)mkdir -p $(STATIC_OBJDIR)

$(SHARED_OBJDIR):
	$(Q)mkdir -p $(SHARED_OBJDIR)

$(STATIC_OBJDIR)/%.o: %.c $(EXTRA_LIB_DEPS) | $(STATIC_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -D LIBXDP_STATIC=1 -Wall -I../../headers -c $< -o $@

$(SHARED_OBJDIR)/%.o: %.c $(EXTRA_LIB_DEPS) | $(SHARED_OBJDIR)
	$(QUIET_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(SHARED_CFLAGS) -Wall -I../../headers -c $< -o $@

XDP_IN_SHARED	:= $(SHARED_OBJDIR)/libxdp.o $(SHARED_OBJDIR)/xsk.o

GLOBAL_SYM_COUNT = $(shell readelf -s --wide $(XDP_IN_SHARED) | \
			   cut -d "@" -f1 | sed 's/_v[0-9]_[0-9]_[0-9].*//' | \
			   sed 's/\[.*\]//' | \
			   awk '/GLOBAL/ && /DEFAULT/ && !/UND/ {print $$NF}' | \
			   sort -u | wc -l)
VERSIONED_SYM_COUNT = $(shell readelf --dyn-syms --wide $(OBJDIR)/libxdp.so | \
			      grep -Eo '[^ ]+@LIBXDP_' | cut -d@ -f1 | sort -u | wc -l)

check: $(CHECK_RULES)

check_abi: $(OBJDIR)/libxdp.so
	@if [ "$(GLOBAL_SYM_COUNT)" != "$(VERSIONED_SYM_COUNT)" ]; then	 \
		echo "Warning: Num of global symbols in $(XDP_IN_SHARED)"	 \
		     "($(GLOBAL_SYM_COUNT)) does NOT match with num of"	 \
		     "versioned symbols in $^ ($(VERSIONED_SYM_COUNT))." \
		     "Please make sure all symbols are"	 \
		     "versioned in $(VERSION_SCRIPT)." >&2;		 \
		readelf -s --wide $(XDP_IN_SHARED) |			 \
		    cut -d "@" -f1 | sed 's/_v[0-9]_[0-9]_[0-9].*//' |	 \
		    sed 's/\[.*\]//' |					 \
		    awk '/GLOBAL/ && /DEFAULT/ && !/UND/ {print $$NF}'|  \
		    sort -u > $(OUTPUT)libxdp_global_syms.tmp;		 \
		readelf --dyn-syms --wide $(OUTPUT)libxdp.so |		 \
		    grep -Eo '[^ ]+@LIBXDP_' | cut -d@ -f1 |		 \
		    sort -u > $(OUTPUT)libxdp_versioned_syms.tmp; 	 \
		diff -u $(OUTPUT)libxdp_global_syms.tmp			 \
		     $(OUTPUT)libxdp_versioned_syms.tmp;		 \
		rm $(OUTPUT)libxdp_global_syms.tmp			 \
		   $(OUTPUT)libxdp_versioned_syms.tmp;			 \
		exit 1;							 \
	fi


$(TEMPLATED_SOURCES): %.c: %.c.in Makefile
	$(QUIET_M4)$(M4) $(DEFINES) $< > $@ || ( ret=$$?; rm -f $@; exit $$ret )

$(EMBEDDED_XDP_OBJS): %.embed.o: %.o
	$(QUIET_GEN)$(LD) -r -b binary -o $@ -z noexecstack --format=binary $<
	$(Q)$(OBJCOPY)  --rename-section .data=.rodata,alloc,load,readonly,data,contents $@

$(XDP_OBJS): %.o: %.c $(BPF_HEADERS) $(LIBMK)
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

.PHONY: man
ifeq ($(EMACS),)
man: ;
else
man: $(MAN_PAGE)
$(MAN_OBJ): README.org $(LIBMK)
	$(Q)$(EMACS) -Q --batch --find-file $< --eval "(progn (require 'ox-man)(org-man-export-to-man))"
	$(Q)touch -r $< $@

$(MAN_PAGE): $(MAN_OBJ) $(LIBMK)
	$(QUIET_GEN)MODDATE=$$(git log -1 --pretty="format:%cI" README.org 2>/dev/null); \
		[ "$$?" -eq "0" ] && DATE=$$(date '+%B %_d, %Y' -d "$$MODDATE") || DATE=$$(date '+%B %_d, %Y'); \
		sed -e "1 s/DATE/$$DATE/" -e "1 s/VERSION/v$(TOOLS_VERSION)/" -e '1,5 s/^.SH "\([^"]\+\) - \([^"]\+\)"/.SH "NAME"\n\1 \\- \2\n.SH "SYNOPSIS"/' $< > $@

endif

.PHONY: test
test: all
	$(Q)$(MAKE) -C $(TEST_DIR) run
