package client

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Client provides high-level multi-server client for OpenADP operations
type Client struct {
	serversURL        string
	fallbackServers   []string
	echoTimeout       time.Duration
	maxWorkers        int
	liveServers       []*EncryptedOpenADPClient
	selectionStrategy ServerSelectionStrategy
	mu                sync.RWMutex
}

// NewClient creates a new high-level OpenADP client with server discovery
func NewClient(serversURL string, fallbackServers []string, echoTimeout time.Duration, maxWorkers int) *Client {
	if fallbackServers == nil {
		fallbackServers = GetFallbackServers()
	}

	if echoTimeout == 0 {
		echoTimeout = 10 * time.Second
	}

	if maxWorkers == 0 {
		maxWorkers = 10
	}

	client := &Client{
		serversURL:        serversURL,
		fallbackServers:   fallbackServers,
		echoTimeout:       echoTimeout,
		maxWorkers:        maxWorkers,
		selectionStrategy: FirstAvailable, // Default strategy
	}

	// Initialize servers
	client.initializeServers()

	return client
}

// NewClientWithServerInfo creates a new OpenADP client with predefined server information
func NewClientWithServerInfo(serverInfos []ServerInfo, echoTimeout time.Duration, maxWorkers int) *Client {
	if echoTimeout == 0 {
		echoTimeout = 10 * time.Second
	}

	if maxWorkers == 0 {
		maxWorkers = 10
	}

	client := &Client{
		serversURL:        "",  // No URL scraping needed
		fallbackServers:   nil, // No fallback needed
		echoTimeout:       echoTimeout,
		maxWorkers:        maxWorkers,
		selectionStrategy: FirstAvailable, // Default strategy
	}

	// Test servers directly with the provided ServerInfo
	client.liveServers = client.testServersConcurrently(serverInfos)

	log.Printf("Initialization complete: %d live servers available", len(client.liveServers))
	client.logServerStatus()

	return client
}

// initializeServers scrapes server list and tests each server for liveness
func (c *Client) initializeServers() {
	var serverInfos []ServerInfo

	// If serversURL is empty, skip scraping and use fallback servers directly
	if c.serversURL == "" {
		log.Println("Skipping server scraping, using provided servers...")
		// Convert fallback URLs to ServerInfo structs
		serverInfos = make([]ServerInfo, len(c.fallbackServers))
		for i, url := range c.fallbackServers {
			serverInfos[i] = ServerInfo{
				URL:       url,
				PublicKey: "", // No public key for fallback servers
				Country:   "Unknown",
			}
		}
	} else {
		log.Println("Scraping server list...")

		// Get full server information including public keys
		scraped, err := GetServers(c.serversURL)
		if err != nil || len(scraped) == 0 {
			log.Printf("Failed to scrape servers from %s, using fallback servers: %v", c.serversURL, err)
			serverInfos = GetFallbackServerInfo()
		} else {
			log.Printf("Found %d servers to test", len(scraped))
			serverInfos = scraped
		}
	}

	// Test servers concurrently for better performance
	c.liveServers = c.testServersConcurrently(serverInfos)

	log.Printf("Initialization complete: %d live servers available", len(c.liveServers))
	c.logServerStatus()
}

// logServerStatus logs the current status of live servers
func (c *Client) logServerStatus() {
	if len(c.liveServers) > 0 {
		log.Println("Live servers:")
		for i, client := range c.liveServers {
			encStatus := "no encryption"
			if client.HasPublicKey() {
				encStatus = "Noise-NK encryption"
			}
			log.Printf("  %d. %s [%s]", i+1, client.URL, encStatus)
		}
	} else {
		log.Println("WARNING: No live servers found! All operations will fail.")
	}
}

// testServersConcurrently tests multiple servers concurrently for liveness using echo
func (c *Client) testServersConcurrently(serverInfos []ServerInfo) []*EncryptedOpenADPClient {
	type result struct {
		client *EncryptedOpenADPClient
		url    string
	}

	results := make(chan result, len(serverInfos))
	var wg sync.WaitGroup

	// Limit concurrent workers
	semaphore := make(chan struct{}, c.maxWorkers)

	for _, serverInfo := range serverInfos {
		wg.Add(1)
		go func(serverInfo ServerInfo) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			client := c.testSingleServerWithInfo(serverInfo)
			results <- result{client: client, url: serverInfo.URL}
		}(serverInfo)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect live servers
	var liveServers []*EncryptedOpenADPClient
	for res := range results {
		if res.client != nil {
			liveServers = append(liveServers, res.client)
		}
	}

	return liveServers
}

// testSingleServerWithInfo tests a single server for liveness using ServerInfo with public key
func (c *Client) testSingleServerWithInfo(serverInfo ServerInfo) *EncryptedOpenADPClient {
	log.Printf("Testing server: %s", serverInfo.URL)

	var publicKey []byte
	var err error

	// Parse public key if available
	if serverInfo.PublicKey != "" {
		publicKey, err = c.parsePublicKey(serverInfo.PublicKey)
		if err != nil {
			log.Printf("  ⚠️  %s: Invalid public key: %v", serverInfo.URL, err)
			publicKey = nil
		}
	}

	// Create encrypted client with public key from servers.json (secure)
	client := NewEncryptedOpenADPClient(serverInfo.URL, publicKey)

	// Test with echo - use a simple test message
	testMessage := fmt.Sprintf("liveness_test_%d", time.Now().Unix())
	result, err := client.Echo(testMessage, false)

	if err != nil {
		log.Printf("  ❌ %s: %v", serverInfo.URL, err)
		return nil
	}

	if result != testMessage {
		log.Printf("  ❌ %s: Echo returned unexpected result: %s", serverInfo.URL, result)
		return nil
	}

	// Check encryption status
	if client.HasPublicKey() {
		log.Printf("  ✅ %s: Live (Noise-NK encryption from servers.json)", serverInfo.URL)
	} else {
		log.Printf("  ✅ %s: Live (no encryption - no public key)", serverInfo.URL)
	}

	return client
}

// parsePublicKey parses a public key in various formats
func (c *Client) parsePublicKey(publicKey string) ([]byte, error) {
	// Handle different key formats
	if strings.HasPrefix(publicKey, "ed25519:") {
		// Remove ed25519: prefix and decode
		keyB64 := strings.TrimPrefix(publicKey, "ed25519:")
		return base64.StdEncoding.DecodeString(keyB64)
	}

	// Assume it's already base64
	return base64.StdEncoding.DecodeString(publicKey)
}

// GetLiveServerCount returns the number of currently live servers
func (c *Client) GetLiveServerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.liveServers)
}

// GetLiveServerURLs returns URLs of all currently live servers
func (c *Client) GetLiveServerURLs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	urls := make([]string, len(c.liveServers))
	for i, client := range c.liveServers {
		urls[i] = client.URL
	}
	return urls
}

// RefreshServers re-scrapes and re-tests all servers to refresh the live server list
func (c *Client) RefreshServers() error {
	log.Println("Refreshing server list...")
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initializeServers()
	return nil // Always succeeds for now
}

// RegisterSecret registers a secret across multiple servers with failover
func (c *Client) RegisterSecret(uid, did, bid string, version, x int, y []byte, maxGuesses, expiration int, authData map[string]interface{}) (bool, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return false, &OpenADPError{
			Code:    ErrorCodeNoLiveServers,
			Message: "No live servers available",
		}
	}

	// Convert y bytes to base64-encoded 32-byte little-endian format (per API spec)
	// The input y bytes are from yInt.Bytes() which returns big-endian minimal bytes
	// We need to convert to 32-byte little-endian format
	yBytes32 := make([]byte, 32)

	// Copy the input bytes to the end of the 32-byte array (big-endian placement)
	copy(yBytes32[32-len(y):], y)

	// Reverse to convert from big-endian to little-endian
	for i, j := 0, len(yBytes32)-1; i < j; i, j = i+1, j-1 {
		yBytes32[i], yBytes32[j] = yBytes32[j], yBytes32[i]
	}

	yStr := base64.StdEncoding.EncodeToString(yBytes32)

	// Try each server until one succeeds
	var lastErr error
	for _, client := range liveServers {
		success, err := client.RegisterSecret("", uid, did, bid, version, x, yStr, maxGuesses, expiration, true, authData)
		if err == nil && success {
			return true, nil
		}
		lastErr = err
		log.Printf("Failed to register with %s: %v", client.URL, err)
	}

	return false, fmt.Errorf("all servers failed, last error: %v", lastErr)
}

// RecoverSecret recovers a secret from servers with failover
func (c *Client) RecoverSecret(authCode, uid, did, bid, b string, guessNum int, authData map[string]interface{}) (map[string]interface{}, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return nil, &OpenADPError{
			Code:    ErrorCodeNoLiveServers,
			Message: "No live servers available",
		}
	}

	// Try each server until one succeeds
	var lastErr error
	for _, client := range liveServers {
		result, err := client.RecoverSecret(authCode, uid, did, bid, b, guessNum, true, authData)
		if err == nil {
			return result, nil
		}
		lastErr = err
		log.Printf("Failed to recover from %s: %v", client.URL, err)
	}

	return nil, fmt.Errorf("all servers failed, last error: %v", lastErr)
}

// ListBackups lists backups for a user from the first available server
func (c *Client) ListBackups(uid string) ([]map[string]interface{}, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return nil, &OpenADPError{
			Code:    ErrorCodeNoLiveServers,
			Message: "No live servers available",
		}
	}

	// Try each server until one succeeds
	var lastErr error
	for _, client := range liveServers {
		result, err := client.ListBackups(uid, false, nil)
		if err == nil {
			return result, nil
		}
		lastErr = err
		log.Printf("Failed to list backups from %s: %v", client.URL, err)
	}

	return nil, fmt.Errorf("all servers failed, last error: %v", lastErr)
}

// Echo sends an echo message to test connectivity
func (c *Client) Echo(message string) (string, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return "", &OpenADPError{
			Code:    ErrorCodeNoLiveServers,
			Message: "No live servers available",
		}
	}

	// Try the first server
	return liveServers[0].Echo(message, false)
}

// Ping tests connectivity to servers
func (c *Client) Ping() error {
	_, err := c.Echo("ping")
	return err
}

// GetServerInfo gets information from the first available server
func (c *Client) GetServerInfo() (map[string]interface{}, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return nil, &OpenADPError{
			Code:    ErrorCodeNoLiveServers,
			Message: "No live servers available",
		}
	}

	return liveServers[0].GetServerInfo()
}

// Standardized Interface Implementation (Phase 3)
// These methods implement the MultiServerClientInterface for cross-language compatibility

// RegisterSecretStandardized implements the standardized interface
func (c *Client) RegisterSecretStandardized(request *RegisterSecretRequest) (*RegisterSecretResponse, error) {
	// Convert Y from base64 string to bytes for legacy method
	yBytes, err := base64.StdEncoding.DecodeString(request.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid Y coordinate: %v", err)
	}

	success, err := c.RegisterSecret(
		request.UID, request.DID, request.BID,
		request.Version, request.X, yBytes,
		request.MaxGuesses, request.Expiration,
		request.AuthData,
	)

	if err != nil {
		return nil, err
	}

	return &RegisterSecretResponse{
		Success: success,
		Message: "",
	}, nil
}

// RecoverSecretStandardized implements the standardized interface
func (c *Client) RecoverSecretStandardized(request *RecoverSecretRequest) (*RecoverSecretResponse, error) {
	result, err := c.RecoverSecret(
		request.AuthCode, "", request.DID, request.BID,
		request.B, request.GuessNum,
		request.AuthData,
	)
	if err != nil {
		return nil, err
	}

	// Convert map response to standardized struct
	version, _ := result["version"].(int)
	x, _ := result["x"].(int)
	siBStr, _ := result["si_b"].(string)
	numGuesses, _ := result["num_guesses"].(int)
	maxGuesses, _ := result["max_guesses"].(int)
	expiration, _ := result["expiration"].(int)

	return &RecoverSecretResponse{
		Version:    version,
		X:          x,
		SiB:        siBStr,
		NumGuesses: numGuesses,
		MaxGuesses: maxGuesses,
		Expiration: expiration,
	}, nil
}

// ListBackupsStandardized implements the standardized interface
func (c *Client) ListBackupsStandardized(request *ListBackupsRequest) (*ListBackupsResponse, error) {
	backups, err := c.ListBackups(request.UID)
	if err != nil {
		return nil, err
	}

	// Convert to standardized format
	standardBackups := make([]BackupInfo, len(backups))
	for i, backup := range backups {
		uid, _ := backup["uid"].(string)
		bid, _ := backup["bid"].(string)
		version, _ := backup["version"].(int)
		numGuesses, _ := backup["num_guesses"].(int)
		maxGuesses, _ := backup["max_guesses"].(int)
		expiration, _ := backup["expiration"].(int)

		standardBackups[i] = BackupInfo{
			UID:        uid,
			BID:        bid,
			Version:    version,
			NumGuesses: numGuesses,
			MaxGuesses: maxGuesses,
			Expiration: expiration,
		}
	}

	return &ListBackupsResponse{
		Backups: standardBackups,
	}, nil
}

// TestConnection implements the standardized interface
func (c *Client) TestConnection() error {
	return c.Ping()
}

// GetServerURL implements the standardized interface (returns first live server)
func (c *Client) GetServerURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.liveServers) > 0 {
		return c.liveServers[0].URL
	}
	return ""
}

// SupportsEncryption implements the standardized interface
func (c *Client) SupportsEncryption() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return true if any live server supports encryption
	for _, server := range c.liveServers {
		if server.SupportsEncryption() {
			return true
		}
	}
	return false
}

// SetServerSelectionStrategy implements the MultiServerClientInterface
func (c *Client) SetServerSelectionStrategy(strategy ServerSelectionStrategy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.selectionStrategy = strategy
}

// GetServerInfoStandardized implements the standardized interface
func (c *Client) GetServerInfoStandardized() (*ServerInfoResponse, error) {
	info, err := c.GetServerInfo()
	if err != nil {
		return nil, err
	}

	// Convert to standardized format
	serverVersion, _ := info["version"].(string)
	noiseKey, _ := info["noise_nk_public_key"].(string)

	methods := []string{"RegisterSecret", "RecoverSecret", "ListBackups", "Echo", "GetServerInfo"}
	if noiseKey != "" {
		methods = append(methods, "noise_handshake", "encrypted_call")
	}

	return &ServerInfoResponse{
		ServerVersion:    serverVersion,
		NoiseNKPublicKey: noiseKey,
		SupportedMethods: methods,
		MaxRequestSize:   1024 * 1024, // 1MB default
		RateLimits:       make(map[string]interface{}),
	}, nil
}
