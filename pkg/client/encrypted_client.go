package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openadp/openadp/pkg/noise"
)

// EncryptedOpenADPClient extends the basic client with optional Noise-NK encryption
type EncryptedOpenADPClient struct {
	*OpenADPClient
	serverPublicKey  []byte
	serverInfoCached bool
}

// NewEncryptedOpenADPClient creates a new encrypted OpenADP client
func NewEncryptedOpenADPClient(url string, serverPublicKey []byte) *EncryptedOpenADPClient {
	baseClient := NewOpenADPClient(url)

	client := &EncryptedOpenADPClient{
		OpenADPClient:   baseClient,
		serverPublicKey: serverPublicKey,
	}

	// Auto-discover server capabilities if no public key provided
	if serverPublicKey == nil {
		client.discoverServerInfo()
	}

	return client
}

// discoverServerInfo auto-discovers server public key and capabilities
func (c *EncryptedOpenADPClient) discoverServerInfo() {
	result, err := c.GetServerInfo()
	if err != nil {
		return // Silently fail, encryption won't be available
	}

	if publicKeyB64, ok := result["noise_nk_public_key"].(string); ok {
		if publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64); err == nil {
			c.serverPublicKey = publicKeyBytes
			c.serverInfoCached = true
		}
	}
}

// makeEncryptedRequest makes an encrypted JSON-RPC request using Noise-NK
func (c *EncryptedOpenADPClient) makeEncryptedRequest(method string, params interface{}, requestID int, authData map[string]interface{}) (interface{}, error) {
	if c.serverPublicKey == nil {
		return nil, fmt.Errorf("server public key not available for encryption")
	}

	// Create Noise-NK client
	noiseClient, err := noise.NewNoiseNK("initiator", nil, c.serverPublicKey, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("failed to create Noise client: %v", err)
	}

	// Step 1: Create the actual JSON-RPC request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      requestID,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Step 2: Start Noise handshake - client writes first message
	handshakeMsg1, err := noiseClient.WriteHandshakeMessage(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write handshake message: %v", err)
	}

	// Step 3: Send handshake message to server
	handshakeRequest := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "NoiseHandshake",
		Params:  []interface{}{base64.StdEncoding.EncodeToString(handshakeMsg1)},
		ID:      requestID,
	}

	handshakeReqBytes, err := json.Marshal(handshakeRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal handshake request: %v", err)
	}

	// Send handshake request
	resp, err := c.HTTPClient.Post(c.URL, "application/json", bytes.NewBuffer(handshakeReqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to send handshake request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("handshake HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	handshakeRespBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %v", err)
	}

	var handshakeResponse JSONRPCResponse
	if err := json.Unmarshal(handshakeRespBytes, &handshakeResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake response: %v", err)
	}

	if handshakeResponse.Error != nil {
		return nil, fmt.Errorf("handshake JSON-RPC error %d: %s", handshakeResponse.Error.Code, handshakeResponse.Error.Message)
	}

	// Step 4: Process server's handshake response
	handshakeMsgB64, ok := handshakeResponse.Result.(string)
	if !ok {
		return nil, fmt.Errorf("invalid handshake response format")
	}

	handshakeMsg2, err := base64.StdEncoding.DecodeString(handshakeMsgB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode handshake message: %v", err)
	}

	// Complete handshake
	serverPayload, err := noiseClient.ReadHandshakeMessage(handshakeMsg2)
	if err != nil {
		return nil, fmt.Errorf("failed to complete handshake: %v", err)
	}

	// Step 5: Parse the encrypted response from server
	var encryptedResponse JSONRPCResponse
	if err := json.Unmarshal(serverPayload, &encryptedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %v", err)
	}

	if encryptedResponse.Error != nil {
		return nil, fmt.Errorf("encrypted JSON-RPC error %d: %s", encryptedResponse.Error.Code, encryptedResponse.Error.Message)
	}

	return encryptedResponse.Result, nil
}

// makeRequest makes encrypted requests using Noise-NK (no fallback to unencrypted)
func (c *EncryptedOpenADPClient) makeRequest(method string, params interface{}, encrypted bool, authData map[string]interface{}) (interface{}, error) {
	c.requestID++

	// Require server public key for all requests - no fallback to unencrypted
	if c.serverPublicKey == nil {
		return nil, fmt.Errorf("server public key not available - encrypted communication required")
	}

	// Always use encrypted request - ignore the encrypted parameter
	return c.makeEncryptedRequest(method, params, c.requestID, authData)
}

// RegisterSecret registers a secret with mandatory encryption
func (c *EncryptedOpenADPClient) RegisterSecret(authCode, did, bid string, version, x int, y string, maxGuesses, expiration int, encrypted bool, authData map[string]interface{}) (bool, error) {
	params := []interface{}{authCode, "", did, bid, version, x, y, maxGuesses, expiration}

	result, err := c.makeRequest("RegisterSecret", params, true, authData)
	if err != nil {
		return false, err
	}

	success, ok := result.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected response type: %T", result)
	}

	return success, nil
}

// RecoverSecret recovers a secret with mandatory encryption
func (c *EncryptedOpenADPClient) RecoverSecret(authCode, did, bid, b string, guessNum int, encrypted bool, authData map[string]interface{}) (map[string]interface{}, error) {
	params := []interface{}{authCode, "", did, bid, b, guessNum}

	result, err := c.makeRequest("RecoverSecret", params, true, authData)
	if err != nil {
		return nil, err
	}

	response, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}

	return response, nil
}

// ListBackups lists backups with mandatory encryption
func (c *EncryptedOpenADPClient) ListBackups(authCode string, encrypted bool, authData map[string]interface{}) ([]map[string]interface{}, error) {
	params := []interface{}{authCode, ""}

	result, err := c.makeRequest("ListBackups", params, true, authData)
	if err != nil {
		return nil, err
	}

	backups, ok := result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}

	// Convert to proper format
	var backupList []map[string]interface{}
	for _, backup := range backups {
		if backupMap, ok := backup.(map[string]interface{}); ok {
			backupList = append(backupList, backupMap)
		}
	}

	return backupList, nil
}

// Echo sends an echo message with mandatory encryption
func (c *EncryptedOpenADPClient) Echo(message string, encrypted bool) (string, error) {
	params := []interface{}{message}

	result, err := c.makeRequest("Echo", params, true, nil)
	if err != nil {
		return "", err
	}

	response, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected response type: %T", result)
	}

	return response, nil
}

// CreateAuthPayload creates authentication payload for OAuth/DPoP (if needed)
func (c *EncryptedOpenADPClient) CreateAuthPayload(accessToken string, privateKey interface{}, publicKeyJWK map[string]interface{}, handshakeHash []byte) map[string]interface{} {
	// This would implement DPoP token creation if needed
	// For now, return basic auth data structure
	return map[string]interface{}{
		"access_token":   accessToken,
		"token_type":     "DPoP",
		"handshake_hash": base64.StdEncoding.EncodeToString(handshakeHash),
	}
}

// MakeAuthenticatedRequest makes an authenticated request with OAuth/DPoP
func (c *EncryptedOpenADPClient) MakeAuthenticatedRequest(method string, params interface{}, accessToken string, privateKey interface{}, publicKeyJWK map[string]interface{}) (interface{}, error) {
	// Create temporary Noise client to get handshake hash
	if c.serverPublicKey == nil {
		return nil, fmt.Errorf("server public key required for authenticated requests")
	}

	noiseClient, err := noise.NewNoiseNK("initiator", nil, c.serverPublicKey, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("failed to create Noise client: %v", err)
	}

	// Perform minimal handshake to get hash
	_, err = noiseClient.WriteHandshakeMessage([]byte("auth"))
	if err != nil {
		return nil, fmt.Errorf("failed to generate handshake: %v", err)
	}

	authData := c.CreateAuthPayload(accessToken, privateKey, publicKeyJWK, noiseClient.GetHandshakeHash())

	return c.makeRequest(method, params, true, authData)
}

// Convenience functions for creating clients

// CreateEncryptedClient creates an encrypted client with auto-discovery
func CreateEncryptedClient(serverURL string, serverPublicKey []byte) *EncryptedOpenADPClient {
	return NewEncryptedOpenADPClient(serverURL, serverPublicKey)
}

// CreateClient creates an encrypted client with auto-discovery (no public key needed)
func CreateClient(serverURL string) *EncryptedOpenADPClient {
	return NewEncryptedOpenADPClient(serverURL, nil)
}

// ParseServerPublicKey parses a base64-encoded server public key
func ParseServerPublicKey(keyB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyB64)
}

// Convenience functions for one-off operations

// RegisterSecretSimple registers a secret using a simple interface with mandatory encryption
func RegisterSecretSimple(authCode, did, bid string, version, x int, y string, maxGuesses, expiration int, serverURL string) (bool, error) {
	client := CreateClient(serverURL)
	return client.RegisterSecret(authCode, did, bid, version, x, y, maxGuesses, expiration, true, nil)
}

// RecoverSecretSimple recovers a secret using a simple interface with mandatory encryption
func RecoverSecretSimple(authCode, did, bid, b string, guessNum int, serverURL string) (map[string]interface{}, error) {
	client := CreateClient(serverURL)
	return client.RecoverSecret(authCode, did, bid, b, guessNum, true, nil)
}

// ListBackupsSimple lists backups using a simple interface with mandatory encryption
func ListBackupsSimple(authCode, serverURL string) ([]map[string]interface{}, error) {
	client := CreateClient(serverURL)
	return client.ListBackups(authCode, true, nil)
}

// EchoSimple sends an echo message using a simple interface with mandatory encryption
func EchoSimple(message, serverURL string) (string, error) {
	client := CreateClient(serverURL)
	return client.Echo(message, true)
}
