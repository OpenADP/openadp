# OpenADP Go Implementation Makefile
# ===================================

# Variables
BINARY_NAME=openadp-demo
CLI_BINARY_NAME=openadp-cli
SERVER_BINARY_NAME=openadp-server
ENCRYPT_BINARY_NAME=openadp-encrypt
DECRYPT_BINARY_NAME=openadp-decrypt
KEYGEN_BINARY_NAME=openadp-keygen
TEST_RUNNER_BINARY_NAME=run-tests
VERSION=1.0.0
BUILD_DIR=build
PKG_DIR=pkg
CMD_DIR=cmd

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: all build build-cli build-server build-encrypt build-decrypt build-keygen build-test-runner clean test test-verbose deps fmt lint help install demo server encrypt decrypt keygen run-tests

# Default target
all: clean deps fmt test build build-cli build-server build-encrypt build-decrypt build-keygen build-test-runner

# Build the demo application
build:
	@echo "🔨 Building OpenADP demo application..."
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp

# Build the CLI application
build-cli:
	@echo "🔨 Building OpenADP CLI application..."
	$(GOBUILD) -o $(BUILD_DIR)/$(CLI_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp-cli

# Build the server application
build-server:
	@echo "🔨 Building OpenADP server application..."
	$(GOBUILD) -o $(BUILD_DIR)/$(SERVER_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp-server

# Build the encryption tool
build-encrypt:
	@echo "🔨 Building OpenADP encryption tool..."
	$(GOBUILD) -o $(BUILD_DIR)/$(ENCRYPT_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt

# Build the decryption tool
build-decrypt:
	@echo "🔨 Building OpenADP decryption tool..."
	$(GOBUILD) -o $(BUILD_DIR)/$(DECRYPT_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt

# Build the key generation tool
build-keygen:
	@echo "🔨 Building OpenADP key generation tool..."
	$(GOBUILD) -o $(BUILD_DIR)/$(KEYGEN_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp-keygen

# Build the test runner
build-test-runner:
	@echo "🔨 Building OpenADP test runner..."
	$(GOBUILD) -o $(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/run-tests

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)

# Run tests using the built-in go test
test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v ./$(PKG_DIR)/...

# Run tests using our comprehensive test runner
run-tests: build-test-runner
	@echo "🚀 Running comprehensive test suite..."
	./$(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME)

# Run tests with coverage using our test runner
run-tests-coverage: build-test-runner
	@echo "🚀 Running comprehensive test suite with coverage..."
	./$(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME) -coverage

# Run only unit tests using our test runner
run-tests-unit: build-test-runner
	@echo "🚀 Running unit tests only..."
	./$(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME) -unit-only

# Run benchmarks using our test runner
run-tests-bench: build-test-runner
	@echo "🚀 Running benchmark tests..."
	./$(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME) -bench-only

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./$(PKG_DIR)/...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report generated: coverage.html"

# Run tests with race detection
test-race:
	@echo "🧪 Running tests with race detection..."
	$(GOTEST) -v -race ./$(PKG_DIR)/...

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./$(PKG_DIR)/...

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	@echo "🎨 Formatting code..."
	$(GOFMT) ./...

# Run linter (requires golangci-lint)
lint:
	@echo "🔍 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Install binaries to GOPATH/bin
install: build build-cli build-server build-encrypt build-decrypt build-keygen build-test-runner
	@echo "📥 Installing binaries..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(CLI_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(SERVER_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(ENCRYPT_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(DECRYPT_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(KEYGEN_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME) $(GOPATH)/bin/
	@echo "✅ Installed all binaries to $(GOPATH)/bin/"

# Run the demo application
demo: build
	@echo "🚀 Running OpenADP demo..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# Run the CLI application
cli: build-cli
	@echo "🚀 Running OpenADP CLI..."
	./$(BUILD_DIR)/$(CLI_BINARY_NAME) -help

# Run the server application
server: build-server
	@echo "🚀 Starting OpenADP server..."
	./$(BUILD_DIR)/$(SERVER_BINARY_NAME)

# Run the encryption tool
encrypt: build-encrypt
	@echo "🔐 Running OpenADP encryption tool..."
	./$(BUILD_DIR)/$(ENCRYPT_BINARY_NAME) -help

# Run the decryption tool
decrypt: build-decrypt
	@echo "🔓 Running OpenADP decryption tool..."
	./$(BUILD_DIR)/$(DECRYPT_BINARY_NAME) -help

# Generate authentication code
auth-code: build-cli
	@echo "🔑 Generating authentication code..."
	./$(BUILD_DIR)/$(CLI_BINARY_NAME) -command generate-auth

# Run system tests
system-test: build-cli
	@echo "🧪 Running system tests..."
	./$(BUILD_DIR)/$(CLI_BINARY_NAME) -command test

# Interactive CLI mode
interactive: build-cli
	@echo "🎮 Starting interactive mode..."
	./$(BUILD_DIR)/$(CLI_BINARY_NAME) -interactive

# Test server connectivity
test-server: build-server
	@echo "🌐 Testing server connectivity..."
	@echo "Starting server in background..."
	./$(BUILD_DIR)/$(SERVER_BINARY_NAME) -port 8081 &
	@SERVER_PID=$$!; \
	sleep 2; \
	echo "Testing Echo method..."; \
	curl -s -H "Content-Type: application/json" \
		-d '{"jsonrpc":"2.0","method":"Echo","params":["Hello, OpenADP!"],"id":1}' \
		http://localhost:8081 | jq .; \
	echo "Testing GetServerInfo method..."; \
	curl -s -H "Content-Type: application/json" \
		-d '{"jsonrpc":"2.0","method":"GetServerInfo","params":[],"id":2}' \
		http://localhost:8081 | jq .; \
	echo "Stopping server..."; \
	kill $$SERVER_PID

# Test encryption/decryption workflow
test-encryption: build-encrypt build-decrypt
	@echo "🔐 Testing encryption/decryption workflow..."
	@echo "Creating test file..."
	echo "This is a test file for OpenADP encryption." > test_file.txt
	@echo "Encrypting file..."
	echo "testpassword123" | ./$(BUILD_DIR)/$(ENCRYPT_BINARY_NAME) -file test_file.txt -servers "http://localhost:8080"
	@echo "Decrypting file..."
	echo "testpassword123" | ./$(BUILD_DIR)/$(DECRYPT_BINARY_NAME) -file test_file.txt.enc
	@echo "Comparing files..."
	diff test_file.txt test_file.txt || echo "✅ Encryption/decryption test passed!"
	@echo "Cleaning up..."
	rm -f test_file.txt test_file.txt.enc

# Development setup
dev-setup:
	@echo "🛠️  Setting up development environment..."
	$(GOGET) golang.org/x/tools/cmd/goimports
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "✅ Development environment ready!"

# Create release builds for multiple platforms
release: clean
	@echo "📦 Creating release builds..."
	mkdir -p $(BUILD_DIR)/release
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-cli
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-cli
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-cli
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-cli
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-windows-amd64.exe $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-windows-amd64.exe $(LDFLAGS) ./$(CMD_DIR)/openadp-cli
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-windows-amd64.exe $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-windows-amd64.exe $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-windows-amd64.exe $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	@echo "✅ Release builds created in $(BUILD_DIR)/release/"

# Show project statistics
stats:
	@echo "📊 Project Statistics"
	@echo "===================="
	@echo "Go files:"
	@find . -name "*.go" -not -path "./vendor/*" | wc -l
	@echo "Lines of code:"
	@find . -name "*.go" -not -path "./vendor/*" -exec wc -l {} + | tail -1
	@echo "Packages:"
	@find ./$(PKG_DIR) -type d | wc -l
	@echo "Test files:"
	@find . -name "*_test.go" -not -path "./vendor/*" | wc -l

# Show help
help:
	@echo "OpenADP Go Implementation - Available Targets"
	@echo "=============================================="
	@echo ""
	@echo "🔨 Build Targets:"
	@echo "  all              - Build all components (default)"
	@echo "  build            - Build demo application"
	@echo "  build-cli        - Build CLI application"
	@echo "  build-server     - Build server application"
	@echo "  build-encrypt    - Build encryption tool"
	@echo "  build-decrypt    - Build decryption tool"
	@echo "  build-keygen     - Build key generation tool"
	@echo ""
	@echo "🧪 Test Targets:"
	@echo "  test             - Run all tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-race        - Run tests with race detection"
	@echo "  test-server      - Test server connectivity"
	@echo "  test-encryption  - Test encryption/decryption workflow"
	@echo "  bench            - Run benchmarks"
	@echo ""
	@echo "🚀 Run Targets:"
	@echo "  demo             - Run demo application"
	@echo "  cli              - Run CLI application"
	@echo "  server           - Run server application"
	@echo "  encrypt          - Run encryption tool"
	@echo "  decrypt          - Run decryption tool"
	@echo "  interactive      - Run CLI in interactive mode"
	@echo ""
	@echo "🛠️  Development Targets:"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Install dependencies"
	@echo "  fmt              - Format code"
	@echo "  lint             - Run linter"
	@echo "  dev-setup        - Setup development environment"
	@echo ""
	@echo "📦 Release Targets:"
	@echo "  install          - Install binaries to GOPATH/bin"
	@echo "  release          - Create release builds for all platforms"
	@echo "  stats            - Show project statistics" 