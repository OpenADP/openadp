// Package client provides JSON-RPC client functionality for OpenADP server communication.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openadp/openadp/pkg/crypto"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC response
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"-"` // Custom unmarshaling
	ID      int           `json:"id"`
}

// JSONRPCError represents a JSON-RPC error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling for JSONRPCResponse
func (r *JSONRPCResponse) UnmarshalJSON(data []byte) error {
	// First, unmarshal into a temporary struct with raw error field
	type TempResponse struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  interface{}     `json:"result,omitempty"`
		Error   json.RawMessage `json:"error,omitempty"`
		ID      int             `json:"id"`
	}

	var temp TempResponse
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Copy the basic fields
	r.JSONRPC = temp.JSONRPC
	r.Result = temp.Result
	r.ID = temp.ID

	// Handle the error field - it could be a string or a structured error
	if len(temp.Error) > 0 {
		// Try to unmarshal as structured error first
		var structuredError JSONRPCError
		if err := json.Unmarshal(temp.Error, &structuredError); err == nil {
			r.Error = &structuredError
		} else {
			// If that fails, try to unmarshal as string
			var stringError string
			if err := json.Unmarshal(temp.Error, &stringError); err == nil {
				r.Error = &JSONRPCError{
					Code:    -32603, // Internal error code
					Message: stringError,
				}
			} else {
				// If both fail, create a generic error
				r.Error = &JSONRPCError{
					Code:    -32603,
					Message: "Unknown error format",
					Data:    string(temp.Error),
				}
			}
		}
	}

	return nil
}

// OpenADPClient represents a client for communicating with OpenADP servers
type OpenADPClient struct {
	URL        string
	HTTPClient *http.Client
	requestID  int
}

// NewOpenADPClient creates a new OpenADP client
func NewOpenADPClient(url string) *OpenADPClient {
	return &OpenADPClient{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		requestID: 1,
	}
}

// Legacy param structs removed - replaced by standardized interface types in interfaces.go

// RecoverSecretResult represents the result of recover_secret method
type RecoverSecretResult struct {
	Version    int             `json:"version"`
	X          int             `json:"x"`
	SiB        *crypto.Point2D `json:"si_b"`
	SiBBytes   []byte          `json:"-"` // Raw bytes from server response
	NumGuesses int             `json:"num_guesses"`
	MaxGuesses int             `json:"max_guesses"`
	Expiration int             `json:"expiration"`
}

// ListBackupsResult represents a backup entry from list_backups
type ListBackupsResult struct {
	UID        string `json:"uid"`
	BID        string `json:"bid"`
	Version    int    `json:"version"`
	NumGuesses int    `json:"num_guesses"`
	MaxGuesses int    `json:"max_guesses"`
	Expiration int    `json:"expiration"`
}

// makeRequest makes a JSON-RPC request to the server
func (c *OpenADPClient) makeRequest(method string, params interface{}) (*JSONRPCResponse, error) {
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      c.requestID,
	}
	c.requestID++

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := c.HTTPClient.Post(c.URL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var response JSONRPCResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", response.Error.Code, response.Error.Message)
	}

	return &response, nil
}

// RegisterSecret registers a secret share with the server
func (c *OpenADPClient) RegisterSecret(uid, did, bid string, version, x int, y string, maxGuesses, expiration int) (bool, error) {
	params := map[string]interface{}{
		"uid":         uid,
		"did":         did,
		"bid":         bid,
		"version":     version,
		"x":           x,
		"y":           y,
		"max_guesses": maxGuesses,
		"expiration":  expiration,
	}

	response, err := c.makeRequest("register_secret", params)
	if err != nil {
		return false, err
	}

	result, ok := response.Result.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected response type: %T", response.Result)
	}

	return result, nil
}

// RecoverSecret recovers a secret share from the server
func (c *OpenADPClient) RecoverSecret(uid, did, bid string, b *crypto.Point2D, guessNum int) (*RecoverSecretResult, error) {
	params := map[string]interface{}{
		"uid":       uid,
		"did":       did,
		"bid":       bid,
		"b":         b,
		"guess_num": guessNum,
	}

	response, err := c.makeRequest("recover_secret", params)
	if err != nil {
		return nil, err
	}

	// Parse the result
	resultData, err := json.Marshal(response.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}

	var result RecoverSecretResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %v", err)
	}

	return &result, nil
}

// ListBackups lists all backups for a user
func (c *OpenADPClient) ListBackups(uid string) ([]ListBackupsResult, error) {
	params := map[string]string{"uid": uid}

	response, err := c.makeRequest("list_backups", params)
	if err != nil {
		return nil, err
	}

	// Parse the result
	resultData, err := json.Marshal(response.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}

	var result []ListBackupsResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %v", err)
	}

	return result, nil
}

// Ping tests connectivity to the server
func (c *OpenADPClient) Ping() error {
	response, err := c.makeRequest("Echo", []string{"ping"})
	if err != nil {
		return err
	}

	result, ok := response.Result.(string)
	if !ok || result != "ping" {
		return fmt.Errorf("unexpected ping response: %v", response.Result)
	}

	return nil
}

// GetServerInfo gets server information
func (c *OpenADPClient) GetServerInfo() (map[string]interface{}, error) {
	response, err := c.makeRequest("GetServerInfo", nil)
	if err != nil {
		return nil, err
	}

	// Response should be a map
	if result, ok := response.Result.(map[string]interface{}); ok {
		return result, nil
	}

	return nil, fmt.Errorf("unexpected response type: %T", response.Result)
}

// ClientManager functionality has been moved to the high-level Client in client.go
// This legacy ClientManager is no longer needed

// Legacy auth methods removed - use EncryptedOpenADPClient for auth code support

// Legacy duplicate auth methods removed - functionality available in EncryptedOpenADPClient
