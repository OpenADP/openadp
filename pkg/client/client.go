package client

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Client provides high-level client for OpenADP operations with multi-server support
type Client struct {
	serversURL      string
	fallbackServers []string
	echoTimeout     time.Duration
	maxWorkers      int
	liveServers     []*EncryptedOpenADPClient
	mu              sync.RWMutex
}

// NewClient creates a new high-level OpenADP client
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
		serversURL:      serversURL,
		fallbackServers: fallbackServers,
		echoTimeout:     echoTimeout,
		maxWorkers:      maxWorkers,
	}

	// Initialize servers
	client.initializeServers()

	return client
}

// initializeServers scrapes server list and tests each server for liveness
func (c *Client) initializeServers() {
	var serverURLs []string

	// If serversURL is empty, skip scraping and use fallback servers directly
	if c.serversURL == "" {
		log.Println("Skipping server scraping, using provided servers...")
		serverURLs = c.fallbackServers
	} else {
		log.Println("Scraping server list...")

		// Scrape server URLs
		scraped, err := ScrapeServerURLs(c.serversURL)
		if err != nil || len(scraped) == 0 {
			log.Printf("Failed to scrape servers from %s, using fallback servers: %v", c.serversURL, err)
			serverURLs = c.fallbackServers
		} else {
			log.Printf("Found %d servers to test", len(scraped))
			serverURLs = scraped
		}
	}

	// Test servers concurrently for better performance
	c.liveServers = c.testServersConcurrently(serverURLs)

	log.Printf("Initialization complete: %d live servers available", len(c.liveServers))
	if len(c.liveServers) > 0 {
		log.Println("Live servers:")
		for i, client := range c.liveServers {
			log.Printf("  %d. %s", i+1, client.URL)
		}
	} else {
		log.Println("WARNING: No live servers found! All operations will fail.")
	}
}

// testServersConcurrently tests multiple servers concurrently for liveness using echo
func (c *Client) testServersConcurrently(serverURLs []string) []*EncryptedOpenADPClient {
	type result struct {
		client *EncryptedOpenADPClient
		url    string
	}

	results := make(chan result, len(serverURLs))
	var wg sync.WaitGroup

	// Limit concurrent workers
	semaphore := make(chan struct{}, c.maxWorkers)

	for _, url := range serverURLs {
		wg.Add(1)
		go func(serverURL string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			client := c.testSingleServer(serverURL)
			results <- result{client: client, url: serverURL}
		}(url)
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

// testSingleServer tests a single server for liveness
func (c *Client) testSingleServer(url string) *EncryptedOpenADPClient {
	log.Printf("Testing server: %s", url)

	// Create encrypted client directly - it will auto-discover server info
	client := CreateClient(url)

	// Test with echo - use a simple test message
	testMessage := fmt.Sprintf("liveness_test_%d", time.Now().Unix())
	result, err := client.Echo(testMessage, false)

	if err != nil {
		log.Printf("  ❌ %s: %v", url, err)
		return nil
	}

	if result != testMessage {
		log.Printf("  ❌ %s: Echo returned unexpected result: %s", url, result)
		return nil
	}

	// Check if server has public key for encryption
	if client.serverPublicKey != nil {
		log.Printf("  ✅ %s: Live (encrypted)", url)
	} else {
		log.Printf("  ✅ %s: Live (no encryption)", url)
	}

	return client
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
func (c *Client) RefreshServers() {
	log.Println("Refreshing server list...")
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initializeServers()
}

// RegisterSecret registers a secret across multiple servers with failover
func (c *Client) RegisterSecret(uid, did, bid string, version, x int, y []byte, maxGuesses, expiration int, authData map[string]interface{}) (bool, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return false, fmt.Errorf("no live servers available")
	}

	// Convert y bytes to string for JSON-RPC
	yStr := string(y)

	// Try each server until one succeeds
	var lastErr error
	for _, client := range liveServers {
		success, err := client.RegisterSecret("", did, bid, version, x, yStr, maxGuesses, expiration, false, authData)
		if err == nil && success {
			return true, nil
		}
		lastErr = err
		log.Printf("Failed to register with %s: %v", client.URL, err)
	}

	return false, fmt.Errorf("all servers failed, last error: %v", lastErr)
}

// RecoverSecret recovers a secret from servers with failover
func (c *Client) RecoverSecret(uid, did, bid, b string, guessNum int, authData map[string]interface{}) (map[string]interface{}, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return nil, fmt.Errorf("no live servers available")
	}

	// Try each server until one succeeds
	var lastErr error
	for _, client := range liveServers {
		result, err := client.RecoverSecret("", did, bid, b, guessNum, false, authData)
		if err == nil {
			return result, nil
		}
		lastErr = err
		log.Printf("Failed to recover from %s: %v", client.URL, err)
	}

	return nil, fmt.Errorf("all servers failed, last error: %v", lastErr)
}

// ListBackups lists backups from the first available server
func (c *Client) ListBackups(uid string) ([]map[string]interface{}, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return nil, fmt.Errorf("no live servers available")
	}

	// Try each server until one succeeds
	var lastErr error
	for _, client := range liveServers {
		result, err := client.ListBackups("", false, nil)
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
		return "", fmt.Errorf("no live servers available")
	}

	// Use the first live server for echo
	return liveServers[0].Echo(message, false)
}

// GetServerInfo gets server information from the first available server
func (c *Client) GetServerInfo() (map[string]interface{}, error) {
	c.mu.RLock()
	liveServers := make([]*EncryptedOpenADPClient, len(c.liveServers))
	copy(liveServers, c.liveServers)
	c.mu.RUnlock()

	if len(liveServers) == 0 {
		return nil, fmt.Errorf("no live servers available")
	}

	// Use the first live server for server info
	return liveServers[0].GetServerInfo()
}
