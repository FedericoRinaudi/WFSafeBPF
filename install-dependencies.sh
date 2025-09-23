#!/bin/bash

# eBPF Packet Dropper - Dependency Installation Script
# This script installs all necessary dependencies for building and running the eBPF project

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for certain operations
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script needs sudo privileges to install system packages"
        log_info "Please run: sudo ./install-dependencies.sh"
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect Linux distribution"
        exit 1
    fi
    
    log_info "Detected distribution: $DISTRO $VERSION"
}

# Install dependencies for Ubuntu/Debian
install_ubuntu_debian() {
    log_info "Installing dependencies for Ubuntu/Debian..."
    
    # Update package list
    apt-get update
    
    # Install essential build tools
    apt-get install -y \
        build-essential \
        gcc \
        make \
        pkg-config
    
    # Install eBPF/BPF dependencies
    apt-get install -y \
        clang-15 \
        llvm-15 \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev
    
    # Install kernel headers (needed for eBPF development)
    apt-get install -y linux-headers-$(uname -r)
    
    # Install additional tools that might be useful
    apt-get install -y \
        bpfcc-tools \
        linux-tools-$(uname -r) \
        linux-tools-generic
    
    # Install netcat for testing
    apt-get install -y netcat-openbsd
    
    log_success "Dependencies installed successfully for Ubuntu/Debian"
}

# Install dependencies for CentOS/RHEL/Fedora
install_redhat() {
    log_info "Installing dependencies for Red Hat based systems..."
    
    if command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
    else
        log_error "Neither dnf nor yum package manager found"
        exit 1
    fi
    
    # Install essential build tools
    $PKG_MGR install -y \
        gcc \
        make \
        pkgconfig \
        kernel-devel
    
    # Install eBPF/BPF dependencies
    $PKG_MGR install -y \
        clang \
        llvm \
        libbpf-devel \
        elfutils-libelf-devel \
        zlib-devel
    
    # Install kernel headers
    $PKG_MGR install -y kernel-headers
    
    # Install additional tools
    $PKG_MGR install -y \
        bcc-tools \
        perf
    
    # Install netcat
    $PKG_MGR install -y nmap-ncat
    
    log_success "Dependencies installed successfully for Red Hat based systems"
}

# Install dependencies for Arch Linux
install_arch() {
    log_info "Installing dependencies for Arch Linux..."
    
    # Update package database
    pacman -Sy
    
    # Install dependencies
    pacman -S --noconfirm \
        base-devel \
        clang \
        llvm \
        libbpf \
        libelf \
        zlib \
        linux-headers \
        bcc \
        perf \
        gnu-netcat
    
    log_success "Dependencies installed successfully for Arch Linux"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check for essential tools
    local tools=("clang-15" "gcc" "make" "pkg-config")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            # Try without version suffix for clang
            if [[ "$tool" == "clang-15" ]] && command -v "clang" &> /dev/null; then
                log_warning "clang-15 not found, but clang is available"
            else
                missing+=("$tool")
            fi
        fi
    done
    
    # Check for development libraries
    local libs=("bpf" "elf" "z")
    for lib in "${libs[@]}"; do
        if ! pkg-config --exists "lib$lib" 2>/dev/null; then
            if ! ldconfig -p | grep -q "lib$lib"; then
                missing+=("lib$lib")
            fi
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_error "Installation verification failed"
        return 1
    else
        log_success "All dependencies verified successfully"
        return 0
    fi
}

# Test build
test_build() {
    log_info "Testing build process..."
    
    cd "$(dirname "$0")/eBPF"
    
    # Clean any existing build artifacts
    make clean 2>/dev/null || true
    
    # Test build
    if make all; then
        log_success "Build test successful"
        make clean  # Clean up test artifacts
    else
        log_error "Build test failed"
        return 1
    fi
}

# Configure system for eBPF
configure_system() {
    log_info "Configuring system for eBPF..."
    
    # Enable BPF syscall (if not already enabled)
    if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
        echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled
        log_success "Enabled unprivileged BPF"
    fi
    
    # Increase memory limits for BPF maps
    if [ -f /proc/sys/kernel/bpf_stats_enabled ]; then
        echo 1 > /proc/sys/kernel/bpf_stats_enabled
        log_success "Enabled BPF statistics"
    fi
    
    # Load BPF filesystem if not already mounted
    if ! mount | grep -q bpffs; then
        mkdir -p /sys/fs/bpf
        mount -t bpf bpffs /sys/fs/bpf
        log_success "Mounted BPF filesystem"
    fi
}

# Main installation process
main() {
    log_info "Starting eBPF Packet Dropper dependency installation..."
    
    check_sudo
    detect_distro
    
    case $DISTRO in
        ubuntu|debian)
            install_ubuntu_debian
            ;;
        centos|rhel|fedora)
            install_redhat
            ;;
        arch|manjaro)
            install_arch
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            log_info "Supported distributions: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch Linux"
            exit 1
            ;;
    esac
    
    configure_system
    
    if verify_installation; then
        log_success "All dependencies installed and verified successfully!"
        
        log_info "Testing build process..."
        if test_build; then
            log_success "Installation complete! You can now build the project with:"
            echo -e "  ${BLUE}cd eBPF && make all${NC}"
        else
            log_warning "Dependencies installed but build test failed"
            log_info "You may need to check your system configuration"
        fi
    else
        log_error "Installation verification failed"
        exit 1
    fi
    
    log_info "Additional useful commands:"
    echo -e "  ${BLUE}cd eBPF && make test${NC}        # Run Blake2s tests"
    echo -e "  ${BLUE}sudo ./loader${NC}              # Run packet dropper"
    echo -e "  ${BLUE}bpftool prog list${NC}          # List loaded BPF programs"
    echo -e "  ${BLUE}bpftool map list${NC}           # List BPF maps"
}

# Run main function
main "$@"