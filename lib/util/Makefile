OBJS := params.o logging.o

LIB_DIR ?= ..
LIBBPF_DIR := $(LIB_DIR)/libbpf/src
CFLAGS += -I$(LIBBPF_DIR)


all: params.o logging.o

$(OBJS): %.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS)
