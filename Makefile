
# SPDX-License-Identifier: GPL-2.0
# Top level Makefile for xdp-tools

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

SUBDIRS=lib xdp-filter xdp-loader xdp-dump

all: config.mk check_submodule
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) -C $$i; done

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " distclean           - remove configuration and build"
	@echo " install             - install binaries on local machine"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"

config.mk:
	sh configure

check_submodule:
	@if `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\

clobber:
	touch config.mk
	$(MAKE) clean
	rm -f config.mk cscope.*

distclean: clobber

clean: check_submodule
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done

install: all
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i install; done
