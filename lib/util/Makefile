include util.mk

LIB_DIR ?= ..

include $(LIB_DIR)/defines.mk

all: $(UTIL_OBJS)

$(UTIL_OBJS): %.o: %.c %.h $(MAKEFILES)
	$(QUIET_CC)$(CC) $(CFLAGS) -Wall -I../../headers -c -o $@ $<

clean:
	$(Q)rm -f $(UTIL_OBJS)
