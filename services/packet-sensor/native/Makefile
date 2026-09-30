CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -fPIC
LDFLAGS ?= -shared

LIB := libxdp_capture.so
SRC := xdp_capture.c

.PHONY: all clean

all: $(LIB)

$(LIB): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) -lbpf -lxdp

clean:
	rm -f $(LIB)
