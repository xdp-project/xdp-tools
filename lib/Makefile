
include ../config.mk
SUBDIRS=util

LIB_DIR = .

all: $(OBJECT_LIBBPF)
	@set -e; \
	for i in $(SUBDIRS); \
	do echo "  $$i"; $(MAKE) $(MFLAGS) -C $$i; done

.PHONY: clean
clean: libbpf_clean
	@for i in $(SUBDIRS); \
	do $(MAKE) $(MFLAGS) -C $$i clean; done

libbpf: $(OBJECT_LIBBPF)

ifeq ($(SYSTEM_LIBBPF),n)

ifeq ($(VERBOSE),0)
P:= >/dev/null
endif
.PHONY: libbpf_clean
libbpf/src/libbpf.a:
	@echo ; echo "  libbpf"
	$(QUIET_CC)$(MAKE) $(MFLAGS) -C libbpf/src $P
	$(QUIET_INSTALL)$(MAKE) $(MFLAGS) -C libbpf/src install_headers DESTDIR=root $P

libbpf_clean:
	$(Q)$(MAKE) $(MFLAGS) -C libbpf/src clean $P

else

libbpf_clean:
	@echo -n
endif
