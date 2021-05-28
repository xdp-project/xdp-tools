# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LIB_DIR = ..

include libxdp.mk
include $(LIB_DIR)/defines.mk
include $(LIB_DIR)/util/util.mk

OBJDIR ?= .
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := libxdp.o xsk.o
XDP_OBJS := xdp-dispatcher.o xsk_def_xdp_prog.o xsk_def_xdp_prog_5.3.o
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))
STATIC_LIBS := $(OBJDIR)/libxdp.a
MAN_PAGE := libxdp.3
MAN_OBJ := ${MAN_PAGE:.3=.man}

SHARED_CFLAGS += -fPIC -DSHARED
LIB_HEADERS := $(wildcard $(HEADER_DIR)/xdp/*.h)
BPF_HEADERS := $(wildcard $(HEADER_DIR)/bpf/*.h) $(wildcard $(HEADER_DIR)/xdp/*.h)
EXTRA_LIB_DEPS := $(OBJECT_LIBBPF) $(LIBMK) $(LIB_OBJS) $(LIB_HEADERS) compat.h libxdp_internal.h xsk_def_xdp_prog.h bpf_instr.h
PC_FILE := $(OBJDIR)/libxdp.pc
TEMPLATED_SOURCES := xdp-dispatcher.c

CFLAGS += -I$(HEADER_DIR) -I$(LIB_DIR)/util
BPF_CFLAGS += -I$(HEADER_DIR)


ifndef BUILD_STATIC_ONLY
	SHARED_LIBS := $(OBJDIR)/libxdp.so \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_MAJOR_VERSION) \
		       $(OBJDIR)/libxdp.so.$(LIBXDP_VERSION)
	VERSION_SCRIPT := libxdp.map
endif

all: $(STATIC_LIBS) $(SHARED_LIBS) $(XDP_OBJS) $(PC_FILE) check man

clean:
	$(Q)rm -f $(STATIC_LIBS) $(STATIC_OBJS) $(SHARED_LIBS) $(SHARED_OBJS) $(XDP_OBJS) $(PC_FILE) $(MAN_OBJ) $(MAN_PAGE) $(TEMPLATED_SOURCES)
	$(Q)for d in $(SHARED_OBJDIR) $(STATIC_OBJDIR); do \
		[ -d "$$d" ] && rmdir "$$d"; done || true

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

XDP_IN_SHARED	:= $(SHARED_OBJDIR)/libxdp.o $(SHARED_OBJDIR)/xsk.o

GLOBAL_SYM_COUNT = $(shell readelf -s --wide $(XDP_IN_SHARED) | \
			   cut -d "@" -f1 | sed 's/_v[0-9]_[0-9]_[0-9].*//' | \
			   sed 's/\[.*\]//' | \
			   awk '/GLOBAL/ && /DEFAULT/ && !/UND/ {print $$NF}' | \
			   sort -u | wc -l)
VERSIONED_SYM_COUNT = $(shell readelf --dyn-syms --wide $(OBJDIR)/libxdp.so | \
			      grep -Eo '[^ ]+@LIBXDP_' | cut -d@ -f1 | sort -u | wc -l)

check: check_abi

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
man:
MAN_FILES :=
else
man: $(MAN_PAGE)
MAN_FILES := $(MAN_PAGE)
$(MAN_OBJ): README.org $(LIBMK)
	$(Q)$(EMACS) -Q --batch --find-file $< --eval "(progn (require 'ox-man)(org-man-export-to-man))"

$(MAN_PAGE): $(MAN_OBJ)
	$(QUIET_GEN)sed -e "1 s/DATE/$(shell date '+%B %_d, %Y')/" -e "1 s/VERSION/v$(TOOLS_VERSION)/" $< > $@

endif
