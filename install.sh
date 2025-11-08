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

    # Map to GoReleaser naming conventions
    case "$OS" in
        linux)
            OS_GORELEASER="Linux"
            ;;
        darwin)
            OS_GORELEASER="Darwin"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64)
            ARCH_GORELEASER="x86_64"
            ;;
        aarch64|arm64)
            ARCH_GORELEASER="arm64"
            ;;
        armv7l|armv7)
            ARCH_GORELEASER="armv7"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    # Determine archive extension
    if [ "$OS" = "linux" ] || [ "$OS" = "darwin" ]; then
        ARCHIVE_EXT="tar.gz"
    else
        ARCHIVE_EXT="zip"
    fi
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

# Download and extract archive
download_binary() {
    # Build GoReleaser archive name: dockershield_0.1.0_Linux_x86_64.tar.gz
    VERSION_NO_V="${LATEST_VERSION#v}"  # Remove 'v' prefix
    ARCHIVE_NAME="${BINARY_NAME}_${VERSION_NO_V}_${OS_GORELEASER}_${ARCH_GORELEASER}.${ARCHIVE_EXT}"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${ARCHIVE_NAME}"
    TMP_DIR="/tmp/${BINARY_NAME}-install-$$"
    TMP_ARCHIVE="${TMP_DIR}/${ARCHIVE_NAME}"

    mkdir -p "$TMP_DIR"

    print_info "Downloading ${ARCHIVE_NAME}..."
    print_info "URL: $DOWNLOAD_URL"

    if command -v curl &> /dev/null; then
        curl -sLf "$DOWNLOAD_URL" -o "$TMP_ARCHIVE" || {
            print_error "Download failed. Please check the URL and your internet connection."
            rm -rf "$TMP_DIR"
            exit 1
        }
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$TMP_ARCHIVE" || {
            print_error "Download failed. Please check the URL and your internet connection."
            rm -rf "$TMP_DIR"
            exit 1
        }
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    print_success "Downloaded successfully"

    # Extract archive
    print_info "Extracting archive..."
    if [ "$ARCHIVE_EXT" = "tar.gz" ]; then
        tar -xzf "$TMP_ARCHIVE" -C "$TMP_DIR" || {
            print_error "Extraction failed"
            rm -rf "$TMP_DIR"
            exit 1
        }
    else
        unzip -q "$TMP_ARCHIVE" -d "$TMP_DIR" || {
            print_error "Extraction failed"
            rm -rf "$TMP_DIR"
            exit 1
        }
    fi

    print_success "Extracted successfully"
}

# Install binary
install_binary() {
    print_info "Installing to $INSTALL_DIR..."

    # Find the binary in extracted files
    BINARY_PATH="${TMP_DIR}/${BINARY_NAME}"

    if [ ! -f "$BINARY_PATH" ]; then
        print_error "Binary not found in archive"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    # Make executable
    chmod +x "$BINARY_PATH"

    # Move to install directory (may require sudo)
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
    else
        print_warning "Requires sudo privileges to install to $INSTALL_DIR"
        sudo mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
    fi

    # Cleanup
    rm -rf "$TMP_DIR"

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
    print_info "Detected platform: ${OS_GORELEASER}_${ARCH_GORELEASER}"

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
