package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServerInfo represents information about an OpenADP server
type ServerInfo struct {
	URL              string `json:"url"`
	PublicKey        string `json:"public_key"`
	Country          string `json:"country"`
	RemainingGuesses int    `json:"remaining_guesses,omitempty"` // -1 means unknown, >=0 means known remaining guesses
}

// ServersResponse represents the JSON response from the server registry
type ServersResponse struct {
	Servers []ServerInfo `json:"servers"`
}

// GetServers fetches server information from the OpenADP registry
func GetServers(registryURL string) ([]ServerInfo, error) {
	if registryURL == "" {
		registryURL = "https://servers.openadp.org"
	}

	var apiURL string
	var body []byte
	var err error

	// Handle file:// URLs differently
	if strings.HasPrefix(registryURL, "file://") {
		// For file URLs, read the file directly
		filePath := strings.TrimPrefix(registryURL, "file://")
		body, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %v", filePath, err)
		}
	} else {
		// For HTTP URLs, ensure the URL ends with /api/servers.json
		if strings.HasSuffix(registryURL, "/api/servers.json") || strings.HasSuffix(registryURL, "/servers.json") {
			apiURL = registryURL
		} else {
			// Append /api/servers.json if not already present
			if strings.HasSuffix(registryURL, "/") {
				apiURL = registryURL + "api/servers.json"
			} else {
				apiURL = registryURL + "/api/servers.json"
			}
		}

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: 30 * time.Second,
		}

		// Create request with realistic User-Agent
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("User-Agent", "OpenADP-Client/1.0")
		req.Header.Set("Accept", "application/json")

		// Make the request
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch servers from %s: %v", apiURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
		}

		// Read response body
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
	}

	// Parse JSON response
	var serversResp ServersResponse
	if err := json.Unmarshal(body, &serversResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	if len(serversResp.Servers) == 0 {
		return nil, fmt.Errorf("no servers found in registry response")
	}

	return serversResp.Servers, nil
}

// GetServerURLs gets just the server URLs (for backward compatibility)
func GetServerURLs(registryURL string) ([]string, error) {
	servers, err := GetServers(registryURL)
	if err != nil {
		return nil, err
	}

	urls := make([]string, len(servers))
	for i, server := range servers {
		urls[i] = server.URL
	}

	return urls, nil
}

// ScrapeServerURLs is an alias for GetServerURLs for backward compatibility
func ScrapeServerURLs(registryURL string) ([]string, error) {
	return GetServerURLs(registryURL)
}

// GetServersByCountry groups servers by country
func GetServersByCountry(registryURL string) (map[string][]ServerInfo, error) {
	servers, err := GetServers(registryURL)
	if err != nil {
		return nil, err
	}

	byCountry := make(map[string][]ServerInfo)
	for _, server := range servers {
		country := server.Country
		if country == "" {
			country = "Unknown"
		}
		byCountry[country] = append(byCountry[country], server)
	}

	return byCountry, nil
}

// GetFallbackServers returns a list of hardcoded fallback servers
func GetFallbackServers() []string {
	return []string{
		"https://xyzzy.openadp.org",
		"https://sky.openadp.org",
		"https://akash.network",
	}
}

// GetFallbackServerInfo returns detailed fallback server information
func GetFallbackServerInfo() []ServerInfo {
	return []ServerInfo{
		{
			URL:              "https://xyzzy.openadp.org",
			PublicKey:        "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder1XyzzyServer12345TestKey",
			Country:          "US",
			RemainingGuesses: -1,
		},
		{
			URL:              "https://sky.openadp.org",
			PublicKey:        "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder2SkyServerTestKey67890Demo",
			Country:          "US",
			RemainingGuesses: -1,
		},
		{
			URL:              "https://akash.network",
			PublicKey:        "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder3AkashNetworkTestKey111Demo",
			Country:          "CA",
			RemainingGuesses: -1,
		},
	}
}

// ConvertURLsToServerInfo converts a list of URLs to ServerInfo structs (for backward compatibility)
func ConvertURLsToServerInfo(urls []string) []ServerInfo {
	serverInfos := make([]ServerInfo, len(urls))
	for i, url := range urls {
		serverInfos[i] = ServerInfo{
			URL:              url,
			PublicKey:        "", // No public key available for URLs
			Country:          "Unknown",
			RemainingGuesses: -1,
		}
	}
	return serverInfos
}

// DiscoverServers attempts to discover servers from registry with fallback
func DiscoverServers(registryURL string) []ServerInfo {
	// Try to fetch from registry first
	if servers, err := GetServers(registryURL); err == nil && len(servers) > 0 {
		return servers
	}

	// Fall back to hardcoded servers
	return GetFallbackServerInfo()
}

// DiscoverServerURLs attempts to discover server URLs from registry with fallback
func DiscoverServerURLs(registryURL string) []string {
	servers := DiscoverServers(registryURL)
	urls := make([]string, len(servers))
	for i, server := range servers {
		urls[i] = server.URL
	}
	return urls
}
