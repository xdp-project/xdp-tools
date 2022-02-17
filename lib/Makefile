
LIBBPF_CFLAGS:=$(if $(CFLAGS),$(CFLAGS),-g -O2 -Werror -Wall) -fPIC

LIB_DIR = .
include defines.mk

SUBDIRS=util testing
.PHONY: $(SUBDIRS)

all: $(SUBDIRS) libxdp

util: libxdp
	@echo; echo "  $@"; $(MAKE) -C $@

testing: libxdp util
	@echo; echo "  $@"; $(MAKE) -C $@

.PHONY: libxdp
libxdp: $(OBJECT_LIBBPF)
	@echo; echo "  $@"; $(MAKE) -C $@

.PHONY: clean
clean: libbpf_clean
	@for i in $(SUBDIRS) libxdp; \
	do $(MAKE) -C $$i clean; done

.PHONY: install
install: libxdp_install
	$(MAKE) -C testing install

.PHONY: libxdp_install
libxdp_install: libxdp
	install -m 0755 -d $(DESTDIR)$(HDRDIR)
	$(MAKE) -C libxdp install

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
