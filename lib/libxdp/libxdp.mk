LIBXDP_VERSION := $(shell sed -ne "/LIBXDP_[0-9\.]\+ {/ {s/LIBXDP_\([0-9\.]\+\) {/\1/;p;}" $(LIB_DIR)/libxdp/libxdp.map | tail -n 1)
LIBXDP_MAJOR_VERSION := $(shell echo $(LIBXDP_VERSION) | sed 's/\..*//')

