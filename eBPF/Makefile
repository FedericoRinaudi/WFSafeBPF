# wf-eval/ebpf/Makefile
# Build: BPF object + user-space loader (libbpf)

BPF_CLANG ?= clang-15
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

# Default target - build everything
all: packet-dropper blake2s-test

# Packet dropper components
packet-dropper: packet_dropper.bpf.o loader

# Blake2s test components  
blake2s-test: blake2s_test.bpf.o blake2s_test_loader

# Individual build rules
packet_dropper.bpf.o: packet_dropper.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(UCFLAGS) $< -o $@ $(ULIBS)

blake2s_test.bpf.o: blake2s_test.bpf.c blake2s.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

blake2s_test_loader: blake2s_test_loader.c
	$(CC) $(UCFLAGS) $< -o $@ $(ULIBS)

# Test execution
test: blake2s-test
	@echo "Running Blake2s eBPF implementation test..."
	@sudo ./blake2s_test_loader

# Clean up
clean:
	rm -f *.bpf.o loader blake2s_test_loader

.PHONY: all packet-dropper blake2s-test test clean
