include util.mk

LIB_DIR ?= ..
LIBBPF_DIR := $(LIB_DIR)/libbpf/src
CFLAGS += -I$(LIBBPF_DIR)


all: $(UTIL_OBJS)

$(UTIL_OBJS): %.o: %.c %.h
	$(CC) $(CFLAGS) -I../../headers -c -o $@ $<

clean:
	rm -f $(UTIL_OBJS)
