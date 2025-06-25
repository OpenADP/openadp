package integration

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/openadp/ocrypt/client"
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

	// Registry server for serving servers.json
	RegistryServer *http.Server
	RegistryPort   int
	RegistryURL    string
	ServersJSON    []byte
	registryMutex  sync.RWMutex
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
	m.StopRegistryServer()
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

// GetServerInfos returns ServerInfo structs with public keys for all managed servers
func (m *TestServerManager) GetServerInfos() ([]client.ServerInfo, error) {
	serverInfos := make([]client.ServerInfo, len(m.Servers))

	for i, server := range m.Servers {
		// Create a basic client to call GetServerInfo
		basicClient := client.NewOpenADPClient(server.URL)
		serverInfo, err := basicClient.GetServerInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to get server info from %s: %v", server.URL, err)
		}

		// Extract public key from server info
		publicKey := ""
		if noiseKey, ok := serverInfo["noise_nk_public_key"].(string); ok && noiseKey != "" {
			publicKey = "ed25519:" + noiseKey
		}

		serverInfos[i] = client.ServerInfo{
			URL:       server.URL,
			PublicKey: publicKey,
			Country:   "Test",
		}
	}

	return serverInfos, nil
}

// StartRegistryServer starts a local HTTP server to serve servers.json
func (m *TestServerManager) StartRegistryServer(port int) error {
	m.RegistryPort = port
	m.RegistryURL = fmt.Sprintf("http://localhost:%d", port)

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/servers.json", m.handleServersJSON)
	mux.HandleFunc("/servers.json", m.handleServersJSON) // Alternative endpoint

	m.RegistryServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	// Start server in background
	go func() {
		if err := m.RegistryServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Registry server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	log.Printf("✅ Started registry server on port %d", port)
	return nil
}

// StopRegistryServer stops the registry HTTP server
func (m *TestServerManager) StopRegistryServer() error {
	if m.RegistryServer != nil {
		return m.RegistryServer.Close()
	}
	return nil
}

// UpdateServersJSON regenerates the servers.json from current test servers
func (m *TestServerManager) UpdateServersJSON() error {
	m.registryMutex.Lock()
	defer m.registryMutex.Unlock()

	// Get current server info
	serverInfos, err := m.GetServerInfos()
	if err != nil {
		return fmt.Errorf("failed to get server info: %v", err)
	}

	// Create registry format
	registry := map[string]interface{}{
		"version": "1.0",
		"updated": time.Now().Format(time.RFC3339),
		"servers": serverInfos,
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal servers.json: %v", err)
	}

	m.ServersJSON = jsonData
	log.Printf("📋 Updated servers.json with %d servers", len(serverInfos))
	return nil
}

// handleServersJSON serves the servers.json endpoint
func (m *TestServerManager) handleServersJSON(w http.ResponseWriter, r *http.Request) {
	m.registryMutex.RLock()
	defer m.registryMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if len(m.ServersJSON) == 0 {
		// Generate on-demand if not available
		serverInfos, err := m.GetServerInfos()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get server info: %v", err), http.StatusInternalServerError)
			return
		}

		registry := map[string]interface{}{
			"version": "1.0",
			"updated": time.Now().Format(time.RFC3339),
			"servers": serverInfos,
		}

		jsonData, err := json.MarshalIndent(registry, "", "  ")
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to marshal JSON: %v", err), http.StatusInternalServerError)
			return
		}

		w.Write(jsonData)
	} else {
		w.Write(m.ServersJSON)
	}
}

// GetRegistryURL returns the URL of the registry server
func (m *TestServerManager) GetRegistryURL() string {
	return m.RegistryURL
}

// StartServersWithRegistry starts test servers and a registry server serving their info
func (m *TestServerManager) StartServersWithRegistry(basePort, serverCount, registryPort int) ([]*TestServer, error) {
	// Start OpenADP servers
	servers, err := m.StartServers(basePort, serverCount)
	if err != nil {
		return nil, fmt.Errorf("failed to start OpenADP servers: %v", err)
	}

	// Start registry server
	if err := m.StartRegistryServer(registryPort); err != nil {
		m.StopAllServers()
		return nil, fmt.Errorf("failed to start registry server: %v", err)
	}

	// Generate and update servers.json
	if err := m.UpdateServersJSON(); err != nil {
		m.Cleanup()
		return nil, fmt.Errorf("failed to generate servers.json: %v", err)
	}

	log.Printf("🌐 Integration test environment ready:")
	log.Printf("   • %d OpenADP servers: ports %d-%d", serverCount, basePort, basePort+serverCount-1)
	log.Printf("   • Registry server: %s", m.RegistryURL)
	log.Printf("   • Registry endpoints: %s/api/servers.json", m.RegistryURL)

	return servers, nil
}
