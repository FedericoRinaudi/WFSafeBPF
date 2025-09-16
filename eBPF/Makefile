# wf-eval/ebpf/Makefile
# Build: BPF object + user-space loader (libbpf)

BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

# Arch mapping for __TARGET_ARCH_*
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
  BPF_CFLAGS += -D__TARGET_ARCH_arm64
endif

# User-space
CC ?= gcc
UCFLAGS := -O2 -g -Wall
ULIBS := -lbpf -lelf -lz

all: packet_dropper.bpf.o loader

packet_dropper.bpf.o: packet_dropper.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(UCFLAGS) $< -o $@ $(ULIBS)

clean:
	rm -f packet_dropper.bpf.o loader
