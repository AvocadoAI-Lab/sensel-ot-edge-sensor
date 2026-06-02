CLANG ?= clang
LLC ?= llc
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRC := xdp_redirect.bpf.c
BPF_OBJ := xdp_redirect.bpf.o

CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_OBJ)
