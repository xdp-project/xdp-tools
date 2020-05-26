
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

UTILS := xdp-filter xdp-loader xdp-dump
SUBDIRS := lib $(UTILS)
.PHONY: check_submodule help clobber distclean clean install test $(SUBDIRS)

all: $(SUBDIRS)

lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

$(UTILS): lib
	@echo; echo $@; $(MAKE) -C $@

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " distclean           - remove configuration and build"
	@echo " install             - install binaries on local machine"
	@echo " test                - run test suite"
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

test: all
	@for i in $(UTILS); \
	do echo; echo test $$i; $(MAKE) -C $$i test; done
