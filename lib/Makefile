

LIB_DIR = .
include defines.mk

SUBDIRS=util libxdp

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
	install -m 0644 $(HEADER_DIR)/xdp/*.h $(DESTDIR)$(HDRDIR)

libbpf: $(OBJECT_LIBBPF)

ifeq ($(SYSTEM_LIBBPF),n)

ifeq ($(VERBOSE),0)
P:= >/dev/null
endif
.PHONY: libbpf_clean
libbpf/src/libbpf.a:
	@echo ; echo "  libbpf"
	$(QUIET_CC)$(MAKE) -C libbpf/src $P
	$(QUIET_INSTALL)$(MAKE) -C libbpf/src install_headers DESTDIR=root $P

libbpf_clean:
	$(Q)$(MAKE) -C libbpf/src clean $P

else

libbpf_clean:
	@echo -n
endif
