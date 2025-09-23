#!/bin/bash

# eBPF Packet Dropper - Ubuntu Dependency Installation Script
# Simplified script for Ubuntu with clang-15 only

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if Ubuntu
if ! grep -qi ubuntu /etc/os-release; then
    log_error "This script is designed for Ubuntu only"
    exit 1
fi

# Check sudo
if [ "$EUID" -ne 0 ]; then
    log_error "Please run with sudo: sudo ./install-dependencies.sh"
    exit 1
fi

log_info "Installing eBPF dependencies for Ubuntu..."

# Update package list
log_info "Updating package list..."
apt-get update

# Essential build tools
log_info "Installing build essentials..."
apt-get install -y \
    build-essential \
    gcc \
    make \
    pkg-config

# eBPF specific dependencies
log_info "Installing eBPF dependencies..."
apt-get install -y \
    clang-15 \
    llvm-15 \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev

# Kernel headers
log_info "Installing kernel headers..."
apt-get install -y linux-headers-$(uname -r)

# BPF tools - try to install what's available
log_info "Installing BPF tools..."
apt-get install -y bpfcc-tools 2>/dev/null || log_warning "bpfcc-tools not available"

# Try to install linux-tools, fallback if specific version not found
log_info "Installing linux-tools..."
if ! apt-get install -y linux-tools-$(uname -r) 2>/dev/null; then
    log_warning "Specific linux-tools version not found, trying generic..."
    apt-get install -y linux-tools-generic || log_warning "linux-tools installation failed"
fi

# Netcat for testing
apt-get install -y netcat-openbsd

log_success "Dependencies installed successfully!"

# Verify clang-15
if command -v clang-15 >/dev/null; then
    log_success "clang-15 installed: $(clang-15 --version | head -1)"
else
    log_error "clang-15 not found!"
    exit 1
fi

# Test build
log_info "Testing build..."
cd "$(dirname "$0")/eBPF"
make clean 2>/dev/null || true

if make all; then
    log_success "Build test successful!"
    make clean
    log_info "Ready to use! Run 'cd eBPF && make all' to build"
else
    log_error "Build test failed"
    exit 1
fi