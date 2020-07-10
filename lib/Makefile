
LIBBPF_CFLAGS:=$(if $(CFLAGS),$(CFLAGS),-g -O2 -Werror -Wall) -fPIC

LIB_DIR = .
include defines.mk

SUBDIRS=util libxdp testing

all: $(OBJECT_LIBBPF)
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo "  $$i"; $(MAKE) -C $$i; done

.PHONY: clean
clean: libbpf_clean
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done

install:
	install -m 0755 -d $(DESTDIR)$(HDRDIR)
	$(MAKE) -C libxdp install
	$(MAKE) -C testing install

libbpf: $(OBJECT_LIBBPF)

# Handle libbpf as git submodule
ifeq ($(SYSTEM_LIBBPF),n)
ifeq ($(VERBOSE),0)
P:= >/dev/null
endif

# Detect submodule libbpf source file changes
LIBBPF_SOURCES := $(wildcard libbpf/src/*.[ch])

.PHONY: libbpf_clean
libbpf/src/libbpf.a: $(LIBBPF_SOURCES)
	@echo ; echo "  libbpf"
	$(QUIET_CC)$(MAKE) -C libbpf/src CFLAGS="$(LIBBPF_CFLAGS)" $P
	$(QUIET_INSTALL)$(MAKE) -C libbpf/src install_headers DESTDIR=root $P

libbpf_clean:
	$(Q)$(MAKE) -C libbpf/src clean $P

else

libbpf_clean:
	@echo -n
endif
