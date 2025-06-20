// Package client provides JSON-RPC client functionality for OpenADP server communication.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"-"` // Custom unmarshaling
	ID      int           `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// UnmarshalJSON handles custom unmarshaling for JSONRPCResponse to support both string and structured errors
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

// OpenADPClient represents a basic JSON-RPC client for communicating with OpenADP servers
type OpenADPClient struct {
	URL        string
	HTTPClient *http.Client
	requestID  int
}

// NewOpenADPClient creates a new basic OpenADP client
func NewOpenADPClient(url string) *OpenADPClient {
	return &OpenADPClient{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		requestID: 1,
	}
}

// RecoverSecretResult represents the result of RecoverSecret method
type RecoverSecretResult struct {
	Version    int             `json:"version"`
	X          int             `json:"x"`
	SiB        *crypto.Point2D `json:"si_b"`
	SiBBytes   []byte          `json:"-"` // Raw bytes from server response
	NumGuesses int             `json:"num_guesses"`
	MaxGuesses int             `json:"max_guesses"`
	Expiration int             `json:"expiration"`
}

// ListBackupsResult represents a backup entry from ListBackups method
type ListBackupsResult struct {
	UID        string `json:"uid"`
	DID        string `json:"did"`
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
// Note: This basic client passes empty auth_code. Use EncryptedOpenADPClient for authentication.
func (c *OpenADPClient) RegisterSecret(uid, did, bid string, version, x int, y string, maxGuesses, expiration int) (bool, error) {
	// Server expects: [auth_code, uid, did, bid, version, x, y, max_guesses, expiration] (9 parameters)
	// Basic client passes empty auth_code
	params := []interface{}{"", uid, did, bid, version, x, y, maxGuesses, expiration}

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

// RecoverSecret recovers a secret share from the server
// Note: This basic client passes empty auth_code. Use EncryptedOpenADPClient for authentication.
func (c *OpenADPClient) RecoverSecret(uid, did, bid string, b *crypto.Point2D, guessNum int) (*RecoverSecretResult, error) {
	// Server expects: [auth_code, uid, did, bid, b, guess_num] (6 parameters)
	// Basic client passes empty auth_code
	params := []interface{}{"", uid, did, bid, b, guessNum}

	response, err := c.makeRequest("RecoverSecret", params)
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
	// Server expects: [uid] (1 parameter)
	params := []interface{}{uid}

	response, err := c.makeRequest("ListBackups", params)
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

// Echo tests connectivity to the server
func (c *OpenADPClient) Echo(message string) (string, error) {
	response, err := c.makeRequest("Echo", []interface{}{message})
	if err != nil {
		return "", err
	}

	result, ok := response.Result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected response type: %T", response.Result)
	}

	if result != message {
		return "", fmt.Errorf("unexpected echo response: got %q, want %q", result, message)
	}

	return result, nil
}

// Ping tests connectivity to the server (alias for Echo with "ping" message)
func (c *OpenADPClient) Ping() error {
	_, err := c.Echo("ping")
	return err
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

// Standardized Interface Implementation (Phase 3)
// These methods implement the OpenADPClientInterface for cross-language compatibility

// RegisterSecretStandardized implements the standardized interface
func (c *OpenADPClient) RegisterSecretStandardized(request *RegisterSecretRequest) (*RegisterSecretResponse, error) {
	// Convert standardized request to legacy method call
	success, err := c.RegisterSecret(
		request.UID, request.DID, request.BID,
		request.Version, request.X, request.Y,
		request.MaxGuesses, request.Expiration,
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
func (c *OpenADPClient) RecoverSecretStandardized(request *RecoverSecretRequest) (*RecoverSecretResponse, error) {
	// Convert base64 point to crypto.Point2D for legacy method
	bBytes, err := base64.StdEncoding.DecodeString(request.B)
	if err != nil {
		return nil, fmt.Errorf("invalid point data: %v", err)
	}

	// Create a Point2D from bytes (simplified - in real implementation would need proper point reconstruction)
	b := &crypto.Point2D{
		X: new(big.Int).SetBytes(bBytes[:16]), // Simplified
		Y: new(big.Int).SetBytes(bBytes[16:]), // Simplified
	}

	result, err := c.RecoverSecret(request.DID, request.BID, "", b, request.GuessNum)
	if err != nil {
		return nil, err
	}

	// Convert Point2D back to base64 string
	siBBytes := append(result.SiB.X.Bytes(), result.SiB.Y.Bytes()...)

	return &RecoverSecretResponse{
		Version:    result.Version,
		X:          result.X,
		SiB:        base64.StdEncoding.EncodeToString(siBBytes),
		NumGuesses: result.NumGuesses,
		MaxGuesses: result.MaxGuesses,
		Expiration: result.Expiration,
	}, nil
}

// ListBackupsStandardized implements the standardized interface
func (c *OpenADPClient) ListBackupsStandardized(request *ListBackupsRequest) (*ListBackupsResponse, error) {
	backups, err := c.ListBackups(request.UID)
	if err != nil {
		return nil, err
	}

	// Convert to standardized format
	standardBackups := make([]BackupInfo, len(backups))
	for i, backup := range backups {
		standardBackups[i] = BackupInfo{
			UID:        backup.UID,
			BID:        backup.BID,
			Version:    backup.Version,
			NumGuesses: backup.NumGuesses,
			MaxGuesses: backup.MaxGuesses,
			Expiration: backup.Expiration,
		}
	}

	return &ListBackupsResponse{
		Backups: standardBackups,
	}, nil
}

// TestConnection implements the standardized interface
func (c *OpenADPClient) TestConnection() error {
	return c.Ping()
}

// GetServerURL implements the standardized interface
func (c *OpenADPClient) GetServerURL() string {
	return c.URL
}

// SupportsEncryption implements the standardized interface
func (c *OpenADPClient) SupportsEncryption() bool {
	return false // Basic client doesn't support encryption
}

// GetServerInfoStandardized implements the standardized interface
func (c *OpenADPClient) GetServerInfoStandardized() (*ServerInfoResponse, error) {
	info, err := c.GetServerInfo()
	if err != nil {
		return nil, err
	}

	// Convert to standardized format
	serverVersion, _ := info["version"].(string)

	return &ServerInfoResponse{
		ServerVersion:    serverVersion,
		NoiseNKPublicKey: "",
		SupportedMethods: []string{"RegisterSecret", "RecoverSecret", "ListBackups", "Echo", "GetServerInfo"},
		MaxRequestSize:   1024 * 1024, // 1MB default
		RateLimits:       make(map[string]interface{}),
	}, nil
}
