# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
TOOL_NAME    := xdpdump
XDP_TARGETS  := xdpdump_bpf xdpdump_xdp
USER_TARGETS := xdpdump
TEST_FILE    := tests/test-xdpdump.sh

# Disable warnings about VLAs not being at the end of a structure when building
# with clang. The code is fine, but clang's complaint coupled with -Werror would
# break the build. See https://github.com/xdp-project/xdp-tools/issues/304
CFLAGS       += "-Wno-gnu-variable-sized-type-not-at-end"
LIB_DIR       = ../lib
USER_LIBS     = -lpcap
MAN_PAGE     := xdpdump.8

include $(LIB_DIR)/common.mk
