#!/bin/bash
# DockerShield Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/adrian13508/dockershield/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
REPO="adrian13508/dockershield"
BINARY_NAME="dockershield"
INSTALL_DIR="/usr/local/bin"

# Functions
print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

# Get latest release version
get_latest_version() {
    print_info "Fetching latest version..."

    # Try to get latest release from GitHub API
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$LATEST_VERSION" ]; then
        print_error "Could not determine latest version"
        exit 1
    fi

    print_info "Latest version: $LATEST_VERSION"
}

# Download binary
download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"
    TMP_FILE="/tmp/${BINARY_NAME}-${LATEST_VERSION}"

    print_info "Downloading from: $DOWNLOAD_URL"

    if command -v curl &> /dev/null; then
        curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$TMP_FILE"
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ ! -f "$TMP_FILE" ]; then
        print_error "Download failed"
        exit 1
    fi

    print_success "Downloaded successfully"
}

# Install binary
install_binary() {
    print_info "Installing to $INSTALL_DIR..."

    # Make executable
    chmod +x "$TMP_FILE"

    # Move to install directory (may require sudo)
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    else
        print_warning "Requires sudo privileges to install to $INSTALL_DIR"
        sudo mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    fi

    print_success "Installed to $INSTALL_DIR/$BINARY_NAME"
}

# Verify installation
verify_installation() {
    if command -v $BINARY_NAME &> /dev/null; then
        VERSION=$($BINARY_NAME version 2>&1 | head -n1)
        print_success "Installation verified: $VERSION"
        return 0
    else
        print_error "Installation verification failed"
        return 1
    fi
}

# Main installation flow
main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  DockerShield Installation Script     ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""

    detect_platform
    print_info "Detected platform: $PLATFORM"

    get_latest_version
    download_binary
    install_binary

    echo ""
    if verify_installation; then
        echo ""
        print_success "Installation complete!"
        echo ""
        echo -e "${GREEN}Get started:${NC}"
        echo "  dockershield scan            # Scan your Docker containers"
        echo "  dockershield scan --verbose  # Detailed output"
        echo "  dockershield --help          # Show all commands"
        echo ""
    else
        print_error "Installation failed"
        exit 1
    fi
}

# Run main installation
main
