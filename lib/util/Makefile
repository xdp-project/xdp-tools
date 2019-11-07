include util.mk

LIB_DIR ?= ..

include ../../config.mk

all: $(UTIL_OBJS)

$(UTIL_OBJS): %.o: %.c %.h
	$(QUIET_CC)$(CC) $(CFLAGS) -Wall -I../../headers -c -o $@ $<

clean:
	$(Q)rm -f $(UTIL_OBJS)
