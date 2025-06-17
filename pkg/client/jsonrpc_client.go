// Package client provides JSON-RPC client functionality for OpenADP server communication.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"encoding/base64"

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

// RegisterSecretParams represents parameters for register_secret method
type RegisterSecretParams struct {
	UID        string `json:"uid"`
	DID        string `json:"did"`
	BID        string `json:"bid"`
	Version    int    `json:"version"`
	X          int    `json:"x"`
	Y          string `json:"y"`
	MaxGuesses int    `json:"max_guesses"`
	Expiration int    `json:"expiration"`
}

// RecoverSecretParams represents parameters for recover_secret method
type RecoverSecretParams struct {
	UID      string          `json:"uid"`
	DID      string          `json:"did"`
	BID      string          `json:"bid"`
	B        *crypto.Point2D `json:"b"`
	GuessNum int             `json:"guess_num"`
}

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
	params := RegisterSecretParams{
		UID:        uid,
		DID:        did,
		BID:        bid,
		Version:    version,
		X:          x,
		Y:          y,
		MaxGuesses: maxGuesses,
		Expiration: expiration,
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
	params := RecoverSecretParams{
		UID:      uid,
		DID:      did,
		BID:      bid,
		B:        b,
		GuessNum: guessNum,
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

// GetServerInfo gets information about the server
func (c *OpenADPClient) GetServerInfo() (map[string]interface{}, error) {
	response, err := c.makeRequest("get_server_info", nil)
	if err != nil {
		return nil, err
	}

	result, ok := response.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", response.Result)
	}

	return result, nil
}

// ClientManager manages multiple OpenADP clients
type ClientManager struct {
	clients     []*OpenADPClient
	liveClients []*OpenADPClient
}

// NewClientManager creates a new client manager
func NewClientManager(serverURLs []string) *ClientManager {
	clients := make([]*OpenADPClient, len(serverURLs))
	for i, url := range serverURLs {
		clients[i] = NewOpenADPClient(url)
	}

	return &ClientManager{
		clients: clients,
	}
}

// TestConnectivity tests connectivity to all servers and updates live clients
func (cm *ClientManager) TestConnectivity() error {
	cm.liveClients = nil

	for _, client := range cm.clients {
		if err := client.Ping(); err == nil {
			cm.liveClients = append(cm.liveClients, client)
		}
	}

	if len(cm.liveClients) == 0 {
		return fmt.Errorf("no live servers available")
	}

	return nil
}

// GetLiveClients returns the list of live clients
func (cm *ClientManager) GetLiveClients() []*OpenADPClient {
	return cm.liveClients
}

// GetLiveClientCount returns the number of live clients
func (cm *ClientManager) GetLiveClientCount() int {
	return len(cm.liveClients)
}

// GetLiveServerURLs returns the URLs of live servers
func (cm *ClientManager) GetLiveServerURLs() []string {
	urls := make([]string, len(cm.liveClients))
	for i, client := range cm.liveClients {
		urls[i] = client.URL
	}
	return urls
}

// RegisterSecretWithAuthCode registers a secret share with the server using authentication codes
func (c *OpenADPClient) RegisterSecretWithAuthCode(authCode, did, bid string, version, x int, y string, maxGuesses, expiration int) (bool, error) {
	// Server expects: [auth_code, uid, did, bid, version, x, y, max_guesses, expiration]
	// When using auth codes, uid is empty string (server derives it from auth_code)
	params := []interface{}{authCode, "", did, bid, version, x, y, maxGuesses, expiration}

	response, err := c.makeRequest("RegisterSecret", params)
	if err != nil {
		return false, err
	}

	result, ok := response.Result.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected response type: %T", response.Result)
	}

	return result, nil
}

// RecoverSecretWithAuthCode recovers a secret share from the server using authentication codes
func (c *OpenADPClient) RecoverSecretWithAuthCode(authCode, did, bid string, b interface{}, guessNum int) (*RecoverSecretResult, error) {
	// Server expects: [auth_code, did, bid, b, guess_num]
	// b can be either [x, y] array (for Python servers) or base64 string (for Go servers)
	params := []interface{}{authCode, did, bid, b, guessNum}

	response, err := c.makeRequest("RecoverSecret", params)
	if err != nil {
		return nil, err
	}

	// Parse the result map
	resultMap, ok := response.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", response.Result)
	}

	// Extract fields from the map
	version, ok := resultMap["version"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid version field")
	}

	x, ok := resultMap["x"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid x field")
	}

	siBBase64, ok := resultMap["si_b"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid si_b field")
	}

	numGuesses, ok := resultMap["num_guesses"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid num_guesses field")
	}

	maxGuesses, ok := resultMap["max_guesses"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid max_guesses field")
	}

	expiration, ok := resultMap["expiration"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid expiration field")
	}

	// Decode si_b from base64
	siBBytes, err := base64.StdEncoding.DecodeString(siBBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode si_b: %v", err)
	}

	return &RecoverSecretResult{
		Version:    int(version),
		X:          int(x),
		SiBBytes:   siBBytes, // Store as bytes for now
		NumGuesses: int(numGuesses),
		MaxGuesses: int(maxGuesses),
		Expiration: int(expiration),
	}, nil
}

// ListBackupsWithAuthCode lists all backups for an authentication code
func (c *OpenADPClient) ListBackupsWithAuthCode(authCode string) ([]ListBackupsResult, error) {
	params := []interface{}{authCode}

	response, err := c.makeRequest("ListBackups", params)
	if err != nil {
		return nil, err
	}

	// Parse the result as array of arrays
	resultArray, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", response.Result)
	}

	var backups []ListBackupsResult
	for _, item := range resultArray {
		backupArray, ok := item.([]interface{})
		if !ok || len(backupArray) < 6 {
			continue // Skip invalid entries
		}

		// Parse backup entry: [uid, bid, version, num_guesses, max_guesses, expiration]
		uid, _ := backupArray[0].(string)
		bid, _ := backupArray[1].(string)
		version, _ := backupArray[2].(float64)
		numGuesses, _ := backupArray[3].(float64)
		maxGuesses, _ := backupArray[4].(float64)
		expiration, _ := backupArray[5].(float64)

		backups = append(backups, ListBackupsResult{
			UID:        uid,
			BID:        bid,
			Version:    int(version),
			NumGuesses: int(numGuesses),
			MaxGuesses: int(maxGuesses),
			Expiration: int(expiration),
		})
	}

	return backups, nil
}
