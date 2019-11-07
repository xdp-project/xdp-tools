include util.mk

LIB_DIR ?= ..
LIBBPF_DIR := $(LIB_DIR)/libbpf/src
CFLAGS += -I$(LIBBPF_DIR)/root/usr/include


all: $(UTIL_OBJS)

$(UTIL_OBJS): %.o: %.c %.h
	$(CC) $(CFLAGS) -Wall -I../../headers -c -o $@ $<

clean:
	rm -f $(UTIL_OBJS)
