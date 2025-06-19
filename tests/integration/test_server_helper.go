package integration

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// TestServer represents a running test server instance
type TestServer struct {
	Port    int
	DBPath  string
	Process *os.Process
	URL     string
}

// TestServerManager manages multiple test servers for integration testing
type TestServerManager struct {
	Servers      []*TestServer
	ServerBinary string
	TempDir      string
}

// NewTestServerManager creates a new test server manager
func NewTestServerManager() (*TestServerManager, error) {
	// Find the server binary
	serverBinary, err := findServerBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to find server binary: %v", err)
	}

	// Create temporary directory for test databases
	tempDir, err := ioutil.TempDir("", "openadp-integration-test-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	return &TestServerManager{
		Servers:      make([]*TestServer, 0),
		ServerBinary: serverBinary,
		TempDir:      tempDir,
	}, nil
}

// findServerBinary locates the openadp-server binary
func findServerBinary() (string, error) {
	// Try different possible locations
	candidates := []string{
		"../../build/openadp-server",
		"../build/openadp-server",
		"./build/openadp-server",
		"openadp-server", // In PATH
		"../../cmd/openadp-server/openadp-server",
		"../cmd/openadp-server/openadp-server",
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			abs, err := filepath.Abs(candidate)
			if err == nil {
				return abs, nil
			}
			return candidate, nil
		}
	}

	// Try building it if we can find the source
	sourcePath := "../../cmd/openadp-server"
	if _, err := os.Stat(sourcePath); err == nil {
		log.Println("Building openadp-server for integration tests...")
		buildCmd := exec.Command("go", "build", "-o", "openadp-server", ".")
		buildCmd.Dir = sourcePath
		if err := buildCmd.Run(); err != nil {
			return "", fmt.Errorf("failed to build server: %v", err)
		}

		builtBinary := filepath.Join(sourcePath, "openadp-server")
		if _, err := os.Stat(builtBinary); err == nil {
			abs, _ := filepath.Abs(builtBinary)
			return abs, nil
		}
	}

	return "", fmt.Errorf("openadp-server binary not found. Please build it first with: go build ./cmd/openadp-server")
}

// StartServer starts a single test server on the specified port
func (m *TestServerManager) StartServer(port int) (*TestServer, error) {
	dbPath := filepath.Join(m.TempDir, fmt.Sprintf("test_server_%d.db", port))

	server := &TestServer{
		Port:   port,
		DBPath: dbPath,
		URL:    fmt.Sprintf("http://localhost:%d", port),
	}

	// Start the server process
	cmd := exec.Command(m.ServerBinary,
		"-port", strconv.Itoa(port),
		"-db", dbPath,
	)

	// For debugging, let's see server output
	// cmd.Stderr = os.Stderr
	// cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start server on port %d: %v", port, err)
	}

	server.Process = cmd.Process
	m.Servers = append(m.Servers, server)

	// Wait a moment for the server to start
	time.Sleep(500 * time.Millisecond)

	// Verify the server is responding
	if !m.isServerReady(server) {
		m.StopServer(server)
		return nil, fmt.Errorf("server on port %d failed to start properly", port)
	}

	return server, nil
}

// isServerReady checks if a server is responding to requests
func (m *TestServerManager) isServerReady(server *TestServer) bool {
	// Try multiple times with increasing delays
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*100) * time.Millisecond)
		}

		// Try to make a simple HTTP request to check if server is ready
		// The server will return 405 Method Not Allowed for GET requests, which is expected
		cmd := exec.Command("curl", "-s", "--max-time", "1", "--connect-timeout", "1", "-w", "%{http_code}", "-o", "/dev/null", server.URL)
		output, err := cmd.Output()
		if err == nil && string(output) == "405" {
			return true
		}
	}
	return false
}

// StartServers starts multiple test servers on consecutive ports starting from basePort
func (m *TestServerManager) StartServers(basePort, count int) ([]*TestServer, error) {
	servers := make([]*TestServer, 0, count)

	for i := 0; i < count; i++ {
		port := basePort + i
		server, err := m.StartServer(port)
		if err != nil {
			// Clean up any servers we've already started
			for _, s := range servers {
				m.StopServer(s)
			}
			return nil, fmt.Errorf("failed to start server %d: %v", i+1, err)
		}
		servers = append(servers, server)
		log.Printf("✅ Started test server %d on port %d", i+1, port)
	}

	return servers, nil
}

// StopServer stops a single test server
func (m *TestServerManager) StopServer(server *TestServer) error {
	if server.Process == nil {
		return nil
	}

	// Send SIGTERM first for graceful shutdown
	if err := server.Process.Signal(syscall.SIGTERM); err != nil {
		// If SIGTERM fails, try SIGKILL
		server.Process.Kill()
	}

	// Wait for process to exit
	server.Process.Wait()

	// Clean up database file
	if server.DBPath != "" {
		os.Remove(server.DBPath)
	}

	return nil
}

// StopAllServers stops all managed test servers
func (m *TestServerManager) StopAllServers() {
	for _, server := range m.Servers {
		m.StopServer(server)
	}
	m.Servers = make([]*TestServer, 0)
}

// Cleanup cleans up all resources including temporary directory
func (m *TestServerManager) Cleanup() {
	m.StopAllServers()
	if m.TempDir != "" {
		os.RemoveAll(m.TempDir)
	}
}

// GetServerURLs returns URLs of all managed servers
func (m *TestServerManager) GetServerURLs() []string {
	urls := make([]string, len(m.Servers))
	for i, server := range m.Servers {
		urls[i] = server.URL
	}
	return urls
}
