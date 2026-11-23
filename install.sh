#!/bin/bash
# Skobel installer.
#
# Downloads a release archive from GitHub, verifies its SHA256 against the
# release's checksums.txt, and installs the binary.
#
#   curl -sSLO https://raw.githubusercontent.com/adrian13508/skobel/main/install.sh
#   less install.sh          # read it first
#   bash install.sh
#
# Environment:
#   SKOBEL_VERSION   release tag to install (default: latest), e.g. v0.2.0
#   INSTALL_DIR            target directory (default: /usr/local/bin)

set -euo pipefail

REPO="adrian13508/skobel"
BINARY_NAME="skobel"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

info() { echo "==> $1"; }
fail() { echo "error: $1" >&2; exit 1; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        fail "need sha256sum or shasum to verify the download"
    fi
}

main() {
    command -v curl >/dev/null 2>&1 || fail "curl is required"

    local os arch version archive base expected actual
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in
        linux|darwin) ;;
        *) fail "unsupported operating system: $os" ;;
    esac

    case "$(uname -m)" in
        x86_64)        arch="x86_64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l|armv7)  arch="armv7" ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
    esac

    version="${SKOBEL_VERSION:-}"
    if [ -z "$version" ]; then
        info "Looking up latest release"
        version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
            grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        [ -n "$version" ] || fail "could not determine latest version"
    fi

    archive="${BINARY_NAME}_${version#v}_${os}_${arch}.tar.gz"
    base="https://github.com/${REPO}/releases/download/${version}"
    tmp=$(mktemp -d) # global: the EXIT trap runs after main returns
    trap 'rm -rf "$tmp"' EXIT

    info "Downloading ${archive} (${version})"
    curl -fsSL "${base}/${archive}" -o "${tmp}/${archive}" || fail "download failed: ${base}/${archive}"
    curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt" || fail "could not download checksums.txt"

    info "Verifying SHA256"
    expected=$(awk -v f="$archive" '$2 == f {print $1}' "${tmp}/checksums.txt")
    [ -n "$expected" ] || fail "${archive} is not listed in checksums.txt"
    actual=$(sha256_of "${tmp}/${archive}")
    [ "$expected" = "$actual" ] || fail "checksum mismatch for ${archive}: expected ${expected}, got ${actual}"

    tar -xzf "${tmp}/${archive}" -C "$tmp" "$BINARY_NAME"
    chmod +x "${tmp}/${BINARY_NAME}"

    info "Installing to ${INSTALL_DIR}/${BINARY_NAME}"
    if [ -w "$INSTALL_DIR" ]; then
        mv "${tmp}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo mv "${tmp}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    "${INSTALL_DIR}/${BINARY_NAME}" version
}

main "$@"
