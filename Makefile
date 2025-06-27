# OpenADP Go Implementation Makefile
# ===================================

# Variables
SERVER_BINARY_NAME=openadp-server
ENCRYPT_BINARY_NAME=openadp-encrypt
DECRYPT_BINARY_NAME=openadp-decrypt
SERVERINFO_BINARY_NAME=openadp-serverinfo
OCRYPT_REGISTER_BINARY_NAME=ocrypt-register
OCRYPT_RECOVER_BINARY_NAME=ocrypt-recover
RUST_ENCRYPT_BINARY_NAME=openadp-encrypt-rust
RUST_DECRYPT_BINARY_NAME=openadp-decrypt-rust
VERSION=1.0.0
BUILD_DIR=build
PKG_DIR=pkg
CMD_DIR=cmd
RUST_SDK_DIR=sdk/rust

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Rust parameters
CARGO=cargo
CARGO_BUILD=$(CARGO) build
CARGO_BUILD_RELEASE=$(CARGO) build --release
CARGO_CLEAN=$(CARGO) clean
CARGO_TEST=$(CARGO) test

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: all build build-server build-encrypt build-decrypt build-serverinfo build-ocrypt-register build-ocrypt-recover build-rust build-rust-encrypt build-rust-decrypt test-rust clean clean-rust test test-verbose deps fmt lint help install encrypt decrypt rust-encrypt rust-decrypt serverinfo ocrypt-register ocrypt-recover fuzz fuzz-server fuzz-crypto fuzz-api fuzz-all fuzz-quick fuzz-extended fuzz-coverage fuzz-clean fuzz-help

# Default target
all: clean deps fmt test build build-server build-encrypt build-decrypt build-serverinfo build-ocrypt-register build-ocrypt-recover build-rust

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

# Build the server info tool
build-serverinfo:
	@echo "🔨 Building OpenADP server info tool..."
	$(GOBUILD) -o $(BUILD_DIR)/$(SERVERINFO_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/openadp-serverinfo

# Build the ocrypt register tool
build-ocrypt-register:
	@echo "🔨 Building Ocrypt register tool..."
	$(GOBUILD) -o $(BUILD_DIR)/$(OCRYPT_REGISTER_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/ocrypt-register

# Build the ocrypt recover tool
build-ocrypt-recover:
	@echo "🔨 Building Ocrypt recover tool..."
	$(GOBUILD) -o $(BUILD_DIR)/$(OCRYPT_RECOVER_BINARY_NAME) $(LDFLAGS) ./$(CMD_DIR)/ocrypt-recover

# Build all Rust tools
build-rust: build-rust-encrypt build-rust-decrypt

# Build the Rust encryption tool
build-rust-encrypt:
	@echo "🦀 Building Rust OpenADP encryption tool..."
	@mkdir -p $(BUILD_DIR)
	@if [ -f "$(RUST_SDK_DIR)/Cargo.toml" ]; then \
		cd $(RUST_SDK_DIR) && $(CARGO_BUILD_RELEASE) --bin openadp-encrypt; \
		cp target/release/openadp-encrypt ../../$(BUILD_DIR)/$(RUST_ENCRYPT_BINARY_NAME); \
		echo "✅ Rust encrypt tool built successfully"; \
	else \
		echo "❌ Rust SDK not found at $(RUST_SDK_DIR)"; \
		exit 1; \
	fi

# Build the Rust decryption tool
build-rust-decrypt:
	@echo "🦀 Building Rust OpenADP decryption tool..."
	@mkdir -p $(BUILD_DIR)
	@if [ -f "$(RUST_SDK_DIR)/Cargo.toml" ]; then \
		cd $(RUST_SDK_DIR) && $(CARGO_BUILD_RELEASE) --bin openadp-decrypt; \
		cp target/release/openadp-decrypt ../../$(BUILD_DIR)/$(RUST_DECRYPT_BINARY_NAME); \
		echo "✅ Rust decrypt tool built successfully"; \
	else \
		echo "❌ Rust SDK not found at $(RUST_SDK_DIR)"; \
		exit 1; \
	fi

# Test Rust tools
test-rust:
	@echo "🦀 Testing Rust OpenADP tools..."
	@if [ -f "$(RUST_SDK_DIR)/Cargo.toml" ]; then \
		cd $(RUST_SDK_DIR) && $(CARGO_TEST); \
		echo "✅ Rust tests completed"; \
	else \
		echo "❌ Rust SDK not found at $(RUST_SDK_DIR)"; \
		exit 1; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	@$(MAKE) clean-rust 2>/dev/null || true

# Clean Rust build artifacts
clean-rust:
	@echo "🦀 Cleaning Rust build artifacts..."
	@if [ -f "$(RUST_SDK_DIR)/Cargo.toml" ]; then \
		cd $(RUST_SDK_DIR) && $(CARGO_CLEAN); \
		rm -f $(BUILD_DIR)/$(RUST_ENCRYPT_BINARY_NAME) $(BUILD_DIR)/$(RUST_DECRYPT_BINARY_NAME); \
		rm -f $(BUILD_DIR)/$(OCRYPT_REGISTER_BINARY_NAME) $(BUILD_DIR)/$(OCRYPT_RECOVER_BINARY_NAME); \
		echo "✅ Rust artifacts cleaned"; \
	else \
		echo "❌ Rust SDK not found at $(RUST_SDK_DIR)"; \
	fi

# Run tests using the built-in go test
test:
	@echo "🧪 Running tests..."
	@echo "Testing server module..."
	cd server && $(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	@echo "Testing server module with coverage..."
	cd server && $(GOTEST) -v -coverprofile=../coverage-server.out ./...
	@echo "📊 Coverage reports generated: coverage-*.out"

# Run tests with race detection
test-race:
	@echo "🧪 Running tests with race detection..."
	@echo "Testing server module with race detection..."
	cd server && $(GOTEST) -v -race ./...

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	@echo "Running benchmarks for server module..."
	cd server && $(GOTEST) -bench=. -benchmem ./...

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
install: build build-server build-encrypt build-decrypt build-serverinfo build-rust
	@echo "📥 Installing binaries..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(SERVER_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(ENCRYPT_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(DECRYPT_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(SERVERINFO_BINARY_NAME) $(GOPATH)/bin/
	cp $(BUILD_DIR)/$(TEST_RUNNER_BINARY_NAME) $(GOPATH)/bin/
	@if [ -f "$(BUILD_DIR)/$(RUST_ENCRYPT_BINARY_NAME)" ]; then \
		cp $(BUILD_DIR)/$(RUST_ENCRYPT_BINARY_NAME) $(GOPATH)/bin/; \
		cp $(BUILD_DIR)/$(RUST_DECRYPT_BINARY_NAME) $(GOPATH)/bin/; \
		echo "✅ Installed Rust binaries to $(GOPATH)/bin/"; \
	fi
	@echo "✅ Installed all binaries to $(GOPATH)/bin/"

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

# Run the server info tool
serverinfo: build-serverinfo
	@echo "📋 Running OpenADP server info tool..."
	./$(BUILD_DIR)/$(SERVERINFO_BINARY_NAME) -help

# Run the ocrypt register tool
ocrypt-register: build-ocrypt-register
	@echo "🔐 Running Ocrypt register tool..."
	./$(BUILD_DIR)/$(OCRYPT_REGISTER_BINARY_NAME) --help

# Run the ocrypt recover tool
ocrypt-recover: build-ocrypt-recover
	@echo "🔓 Running Ocrypt recover tool..."
	./$(BUILD_DIR)/$(OCRYPT_RECOVER_BINARY_NAME) --help

# Run the Rust encryption tool
rust-encrypt: build-rust-encrypt
	@echo "🦀 Running Rust OpenADP encryption tool..."
	./$(BUILD_DIR)/$(RUST_ENCRYPT_BINARY_NAME) --help

# Run the Rust decryption tool
rust-decrypt: build-rust-decrypt
	@echo "🦀 Running Rust OpenADP decryption tool..."
	./$(BUILD_DIR)/$(RUST_DECRYPT_BINARY_NAME) --help

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
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-linux-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-linux-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-darwin-amd64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(SERVER_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-server
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(ENCRYPT_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-encrypt
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/release/$(DECRYPT_BINARY_NAME)-darwin-arm64 $(LDFLAGS) ./$(CMD_DIR)/openadp-decrypt
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/release/$(BINARY_NAME)-windows-amd64.exe $(LDFLAGS) ./$(CMD_DIR)/openadp
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
	@find ./common ./client ./server -type d | wc -l
	@echo "Test files:"
	@find . -name "*_test.go" -not -path "./vendor/*" | wc -l

# Show help
help:
	@echo "OpenADP Go Implementation - Available Targets"
	@echo "=============================================="
	@echo ""
	@echo "🔨 Build Targets:"
	@echo "  all              - Build all components (default)"
	@echo "  build-server     - Build server application"
	@echo "  build-encrypt    - Build encryption tool"
	@echo "  build-decrypt    - Build decryption tool"
	@echo "  build-ocrypt-register - Build Ocrypt register tool"
	@echo "  build-ocrypt-recover - Build Ocrypt recover tool"
	@echo "  build-rust       - Build all Rust tools"
	@echo "  build-rust-encrypt - Build Rust encryption tool"
	@echo "  build-rust-decrypt - Build Rust decryption tool"
	@echo ""
	@echo "🧪 Test Targets:"
	@echo "  test             - Run all tests"
	@echo "  test-rust        - Run Rust tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-race        - Run tests with race detection"
	@echo "  test-server      - Test server connectivity"
	@echo "  test-encryption  - Test encryption/decryption workflow"
	@echo "  bench            - Run benchmarks"
	@echo ""
	@echo "🚀 Run Targets:"
	@echo "  server           - Run server application"
	@echo "  encrypt          - Run encryption tool"
	@echo "  decrypt          - Run decryption tool"
	@echo "  ocrypt-register  - Run Ocrypt register tool"
	@echo "  ocrypt-recover   - Run Ocrypt recover tool"
	@echo "  rust-encrypt     - Run Rust encryption tool"
	@echo "  rust-decrypt     - Run Rust decryption tool"
	@echo ""
	@echo "🏗️  Node Operator Targets:"
	@echo "  install-node     - Install/update OpenADP node (requires sudo)"
	@echo "  update-node      - Quick update node (skip system deps, sudo)"
	@echo "  node-status      - Show node service status"
	@echo "  node-logs        - Show recent node logs"
	@echo "  node-test        - Test node health and functionality"
	@echo "  operator-help    - Show detailed operator help"
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

# Fuzz testing targets
.PHONY: fuzz fuzz-server fuzz-crypto fuzz-api fuzz-all

# Run all fuzz tests for a short duration (useful for CI)
fuzz-quick:
	@echo "Running quick fuzz tests..."
	cd server && go test -fuzz=FuzzRegisterInputs -fuzztime=10s ./server
	cd server && go test -fuzz=FuzzRecoverInputs -fuzztime=10s ./server
	cd common && go test -fuzz=FuzzPoint2D -fuzztime=10s ./crypto
	go test -fuzz=FuzzJSONRPCRequest -fuzztime=10s ./cmd/openadp-server

# Run server-specific fuzz tests
fuzz-server:
	@echo "Running server fuzz tests..."
	go test -fuzz=FuzzRegisterInputs -fuzztime=1m ./server/server
	go test -fuzz=FuzzRecoverInputs -fuzztime=1m ./server/server  
	go test -fuzz=FuzzRegisterSecretE2E -fuzztime=1m ./server/server
	go test -fuzz=FuzzRecoverSecretE2E -fuzztime=1m ./server/server
	go test -fuzz=FuzzPointValid -fuzztime=30s ./server/server
	go test -fuzz=FuzzServerInfo -fuzztime=30s ./server/server
	go test -fuzz=FuzzEcho -fuzztime=30s ./server/server
	go test -fuzz=FuzzListBackups -fuzztime=1m ./server/server
	go test -fuzz=FuzzJSONSerialization -fuzztime=1m ./server/server
	go test -fuzz=FuzzConcurrentAccess -fuzztime=30s ./server/server

# Run cryptography fuzz tests
fuzz-crypto:
	@echo "Running crypto fuzz tests..."
	go test -fuzz=FuzzPoint2D -fuzztime=1m ./common/crypto
	go test -fuzz=FuzzPoint4D -fuzztime=1m ./common/crypto
	go test -fuzz=FuzzScalarMult -fuzztime=2m ./common/crypto
	go test -fuzz=FuzzPointAdd -fuzztime=2m ./common/crypto
	go test -fuzz=FuzzX25519Operations -fuzztime=1m ./common/crypto
	go test -fuzz=FuzzHashFunctions -fuzztime=1m ./common/crypto
	go test -fuzz=FuzzRandomBytes -fuzztime=30s ./common/crypto
	go test -fuzz=FuzzPointConversions -fuzztime=1m ./common/crypto
	go test -fuzz=FuzzBigIntOperations -fuzztime=1m ./common/crypto

# Run API endpoint fuzz tests
fuzz-api:
	@echo "Running API fuzz tests..."
	go test -fuzz=FuzzJSONRPCRequest -fuzztime=2m ./cmd/openadp-server
	go test -fuzz=FuzzEchoMethod -fuzztime=1m ./cmd/openadp-server
	go test -fuzz=FuzzRegisterSecretMethod -fuzztime=2m ./cmd/openadp-server
	go test -fuzz=FuzzRecoverSecretMethod -fuzztime=2m ./cmd/openadp-server
	go test -fuzz=FuzzListBackupsMethod -fuzztime=1m ./cmd/openadp-server
	go test -fuzz=FuzzHTTPMethods -fuzztime=1m ./cmd/openadp-server
	go test -fuzz=FuzzParameterTypes -fuzztime=1m ./cmd/openadp-server
	go test -fuzz=FuzzConcurrentRequests -fuzztime=1m ./cmd/openadp-server
	go test -fuzz=FuzzLargePayloads -fuzztime=1m ./cmd/openadp-server
	go test -fuzz=FuzzHealthEndpoint -fuzztime=30s ./cmd/openadp-server

# Run extended fuzz tests (longer duration)
fuzz-extended:
	@echo "Running extended fuzz tests (5 minutes each)..."
	go test -fuzz=FuzzRegisterSecretE2E -fuzztime=5m ./server/server
	go test -fuzz=FuzzRecoverSecretE2E -fuzztime=5m ./server/server
	go test -fuzz=FuzzScalarMult -fuzztime=5m ./common/crypto
	go test -fuzz=FuzzPointAdd -fuzztime=5m ./common/crypto
	go test -fuzz=FuzzJSONRPCRequest -fuzztime=5m ./cmd/openadp-server
	go test -fuzz=FuzzRegisterSecretMethod -fuzztime=5m ./cmd/openadp-server

# Run all fuzz tests with moderate duration
fuzz-all: fuzz-server fuzz-crypto fuzz-api

# Run specific fuzz test with custom duration
# Usage: make fuzz-custom FUZZ=FuzzRegisterInputs PACKAGE=./server/server DURATION=30s
fuzz-custom:
	@echo "Running custom fuzz test: $(FUZZ) for $(DURATION)..."
	go test -fuzz=$(FUZZ) -fuzztime=$(DURATION) $(PACKAGE)

# Generate fuzz test coverage report
fuzz-coverage:
	@echo "Generating fuzz test coverage..."
	mkdir -p coverage
	go test -fuzz=FuzzRegisterInputs -fuzztime=1m -coverprofile=coverage/fuzz-server.out ./server/server
	go test -fuzz=FuzzPoint2D -fuzztime=1m -coverprofile=coverage/fuzz-crypto.out ./common/crypto
	go test -fuzz=FuzzJSONRPCRequest -fuzztime=1m -coverprofile=coverage/fuzz-api.out ./cmd/openadp-server
	go tool cover -html=coverage/fuzz-server.out -o coverage/fuzz-server.html
	go tool cover -html=coverage/fuzz-crypto.out -o coverage/fuzz-crypto.html
	go tool cover -html=coverage/fuzz-api.out -o coverage/fuzz-api.html
	@echo "Coverage reports generated in coverage/ directory"

# Clean up fuzz test artifacts
fuzz-clean:
	@echo "Cleaning up fuzz test artifacts..."
	find . -name "fuzz_*.db" -delete
	find . -path "*/testdata/fuzz/*" -delete
	rm -rf coverage/fuzz-*.out coverage/fuzz-*.html

# Show fuzz test help
fuzz-help:
	@echo "OpenADP Fuzz Testing Targets:"
	@echo ""
	@echo "  fuzz-quick      - Run quick fuzz tests (10s each, good for CI)"
	@echo "  fuzz-server     - Run server business logic fuzz tests"
	@echo "  fuzz-crypto     - Run cryptographic operation fuzz tests" 
	@echo "  fuzz-api        - Run HTTP/JSON-RPC API fuzz tests"
	@echo "  fuzz-all        - Run all fuzz tests with moderate duration"
	@echo "  fuzz-extended   - Run extended fuzz tests (5m each)"
	@echo "  fuzz-coverage   - Generate coverage reports for fuzz tests"
	@echo "  fuzz-clean      - Clean up fuzz test artifacts"
	@echo ""
	@echo "Custom usage:"
	@echo "  make fuzz-custom FUZZ=FuzzRegisterInputs PACKAGE=./server/server DURATION=30s"
	@echo ""
	@echo "Examples:"
	@echo "  make fuzz-server                    # Test server logic"
	@echo "  make fuzz-crypto                    # Test crypto operations"
	@echo "  make fuzz-api                       # Test API endpoints"
	@echo "  make fuzz-quick                     # Quick CI-friendly tests"

# Operator automation targets
.PHONY: install-node update-node node-status node-logs node-test

install-node: ## Install/update OpenADP node (requires sudo)
	@echo "Installing/updating OpenADP node..."
	sudo ./scripts/update-openadp-node.sh

update-node: ## Quick update of OpenADP node (skip deps, requires sudo)
	@echo "Quick updating OpenADP node..."
	sudo ./scripts/update-openadp-node.sh --skip-deps

node-status: ## Show OpenADP node service status
	@echo "OpenADP node service status:"
	@systemctl is-active openadp-server 2>/dev/null && echo "✓ Service is running" || echo "✗ Service is not running"
	@echo ""
	@systemctl status openadp-server --no-pager -l 2>/dev/null || echo "Service not installed"

node-logs: ## Show OpenADP node logs
	@echo "Recent OpenADP node logs:"
	@journalctl -u openadp-server -n 50 --no-pager 2>/dev/null || echo "No logs available"

node-test: ## Test OpenADP node health and functionality
	@echo "Testing OpenADP node..."
	@echo "Health check:"
	@curl -s http://localhost:8080/health 2>/dev/null && echo " ✓ Health check passed" || echo " ✗ Health check failed"
	@echo "Echo test:"
	@curl -s -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"Echo","params":["Test"],"id":1}' http://localhost:8080 2>/dev/null | jq -e '.result' >/dev/null && echo " ✓ Echo test passed" || echo " ✗ Echo test failed"
	@echo "Server info:"
	@curl -s -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"GetServerInfo","params":[],"id":1}' http://localhost:8080 2>/dev/null | jq '.result' 2>/dev/null || echo " ✗ Server info failed"

# Operator help
operator-help: ## Show operator commands
	@echo ""
	@echo "$(CYAN)OpenADP Node Operator Commands:$(NC)"
	@echo ""
	@echo "  $(GREEN)make install-node$(NC)  - Install or update OpenADP node (full)"
	@echo "  $(GREEN)make update-node$(NC)   - Quick update OpenADP node (skip system deps)"
	@echo "  $(GREEN)make node-status$(NC)   - Show service status"
	@echo "  $(GREEN)make node-logs$(NC)     - Show recent service logs"
	@echo "  $(GREEN)make node-test$(NC)     - Test node health and functionality"
	@echo ""
	@echo "  $(YELLOW)Direct script usage:$(NC)"
	@echo "    $(GREEN)sudo ./scripts/update-openadp-node.sh$(NC)            # Full install/update"
	@echo "    $(GREEN)sudo ./scripts/update-openadp-node.sh --dry-run$(NC)   # Preview changes"
	@echo "    $(GREEN)sudo ./scripts/update-openadp-node.sh --skip-deps$(NC) # Quick update"
	@echo "    $(GREEN)./scripts/update-openadp-node.sh --help$(NC)          # Show all options"
	@echo "" 
