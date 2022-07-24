include util.mk

LIB_DIR ?= ..

include $(LIB_DIR)/defines.mk
include $(LIBXDP_DIR)/libxdp.mk

all: $(UTIL_OBJS)

# Create expansions for dependencies
UTIL_H := ${UTIL_OBJS:.o=.h}

$(UTIL_OBJS): %.o: %.c $(UTIL_H) $(LIBMK)
	$(QUIET_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -Wall -I../../headers -c -o $@ $<

clean:
	$(Q)rm -f $(UTIL_OBJS)
