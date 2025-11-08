# Makefile for DockerShield

# Build variables
BINARY_NAME=dockershield
CMD_PATH=./cmd/dockershield
BUILD_DIR=./build
VERSION?=0.1.0-dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

.PHONY: all build clean test run install help build-all release

## all: Default target - builds the binary
all: build

## build: Compile the binary
build:
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "✓ Build complete: ./$(BINARY_NAME)"

## clean: Remove built binaries
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)
	@echo "✓ Clean complete"

## test: Run tests
test:
	@echo "Running tests..."
	go test -v ./...

## run: Build and run the scanner
run: build
	./$(BINARY_NAME) scan

## install: Install binary to $GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) $(CMD_PATH)
	@echo "✓ Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## lint: Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	golangci-lint run

## dev: Quick development build and run
dev:
	@go build $(LDFLAGS) -o $(BINARY_NAME) $(CMD_PATH) && ./$(BINARY_NAME) scan

## help: Show this help message
help:
	@echo "DockerShield - Makefile commands:"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build-all: Build for all platforms
build-all:
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)

	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)

	@echo "Building for Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_PATH)

	@echo "Building for Linux (arm)..."
	GOOS=linux GOARCH=arm go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm $(CMD_PATH)

	@echo "Building for macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)

	@echo "Building for macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)

	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)

	@echo "✓ All builds complete in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

## release: Create release builds with checksums
release: build-all
	@echo "Generating checksums..."
	cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)-* > checksums.txt
	@echo "✓ Release ready in $(BUILD_DIR)/"
	@echo ""
	@echo "Files:"
	@ls -lh $(BUILD_DIR)/
	@echo ""
	@echo "Checksums:"
	@cat $(BUILD_DIR)/checksums.txt
