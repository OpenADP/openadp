package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openadp/openadp/pkg/noise"
)

// EncryptedOpenADPClient extends the basic client with Noise-NK encryption support
type EncryptedOpenADPClient struct {
	URL             string
	HTTPClient      *http.Client
	requestID       int
	serverPublicKey []byte // Ed25519 public key for Noise-NK
}

// NewEncryptedOpenADPClient creates a new encrypted OpenADP client
func NewEncryptedOpenADPClient(url string, serverPublicKey []byte) *EncryptedOpenADPClient {
	return &EncryptedOpenADPClient{
		URL:             url,
		serverPublicKey: serverPublicKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		requestID: 1,
	}
}

// HasPublicKey returns true if the client has a server public key for encryption
func (c *EncryptedOpenADPClient) HasPublicKey() bool {
	return len(c.serverPublicKey) > 0
}

// makeRequest makes a JSON-RPC request with optional Noise-NK encryption
func (c *EncryptedOpenADPClient) makeRequest(method string, params interface{}, encrypted bool, authData map[string]interface{}) (interface{}, error) {
	if encrypted && !c.HasPublicKey() {
		return nil, fmt.Errorf("encryption requested but no server public key available")
	}

	if encrypted {
		return c.makeEncryptedRequest(method, params, authData)
	}

	return c.makeUnencryptedRequest(method, params)
}

// makeUnencryptedRequest makes a standard JSON-RPC request without encryption
func (c *EncryptedOpenADPClient) makeUnencryptedRequest(method string, params interface{}) (interface{}, error) {
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

	return response.Result, nil
}

// makeEncryptedRequest makes a Noise-NK encrypted JSON-RPC request
func (c *EncryptedOpenADPClient) makeEncryptedRequest(method string, params interface{}, authData map[string]interface{}) (interface{}, error) {
	// Step 1: Generate session ID
	sessionID, err := GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	// Step 2: Create Noise client
	noiseClient, err := noise.NewNoiseNK("initiator", nil, c.serverPublicKey, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("failed to create Noise client: %v", err)
	}

	// Step 3: Start handshake
	handshakeMsg1, err := noiseClient.WriteHandshakeMessage([]byte("test"))
	if err != nil {
		return nil, fmt.Errorf("failed to create handshake message: %v", err)
	}

	// Step 4: Send handshake to server
	requestID := c.requestID
	c.requestID++

	handshakeRequest := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "noise_handshake",
		Params: []interface{}{
			map[string]interface{}{
				"session": sessionID,
				"message": base64.StdEncoding.EncodeToString(handshakeMsg1),
			},
		},
		ID: requestID,
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

	handshakeRespBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake response: %v", err)
	}

	var handshakeResponse JSONRPCResponse
	if err := json.Unmarshal(handshakeRespBody, &handshakeResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake response: %v", err)
	}

	if handshakeResponse.Error != nil {
		return nil, fmt.Errorf("handshake JSON-RPC error %d: %s", handshakeResponse.Error.Code, handshakeResponse.Error.Message)
	}

	// Step 5: Process server's handshake response
	handshakeResult, ok := handshakeResponse.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid handshake response format")
	}

	handshakeMsgB64, ok := handshakeResult["message"].(string)
	if !ok {
		return nil, fmt.Errorf("handshake response missing message field")
	}

	handshakeMsg2, err := base64.StdEncoding.DecodeString(handshakeMsgB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode handshake message: %v", err)
	}

	// Complete handshake
	_, err = noiseClient.ReadHandshakeMessage(handshakeMsg2)
	if err != nil {
		return nil, fmt.Errorf("failed to complete handshake: %v", err)
	}

	// Step 6: Prepare the actual method call
	methodCall := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      requestID,
	}

	// Add auth data if provided
	if authData != nil {
		methodCall["auth"] = authData
	}

	// Serialize method call
	methodCallBytes, err := json.Marshal(methodCall)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal method call: %v", err)
	}

	// Step 7: Encrypt the method call
	encryptedCall, err := noiseClient.Encrypt(methodCallBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt method call: %v", err)
	}

	// Step 8: Send encrypted call to server
	encryptedRequest := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "encrypted_call",
		Params: []interface{}{
			map[string]interface{}{
				"session": sessionID,
				"data":    base64.StdEncoding.EncodeToString(encryptedCall),
			},
		},
		ID: requestID + 1, // Different ID for second round
	}

	encryptedReqBytes, err := json.Marshal(encryptedRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted request: %v", err)
	}

	// Send encrypted request
	resp2, err := c.HTTPClient.Post(c.URL, "application/json", bytes.NewBuffer(encryptedReqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to send encrypted request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("encrypted call HTTP error: %d %s", resp2.StatusCode, resp2.Status)
	}

	encryptedRespBody, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted response: %v", err)
	}

	var encryptedResponse JSONRPCResponse
	if err := json.Unmarshal(encryptedRespBody, &encryptedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %v", err)
	}

	if encryptedResponse.Error != nil {
		return nil, fmt.Errorf("encrypted call JSON-RPC error %d: %s", encryptedResponse.Error.Code, encryptedResponse.Error.Message)
	}

	// Step 9: Decrypt the response
	// Server returns {"data": "base64_encrypted_data"}
	resultObj, ok := encryptedResponse.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid encrypted response format")
	}

	encryptedDataB64, ok := resultObj["data"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted response missing data field")
	}

	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	decryptedData, err := noiseClient.Decrypt(encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %v", err)
	}

	// Parse decrypted JSON-RPC response
	var decryptedResponse JSONRPCResponse
	if err := json.Unmarshal(decryptedData, &decryptedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted response: %v", err)
	}

	if decryptedResponse.Error != nil {
		return nil, fmt.Errorf("decrypted JSON-RPC error %d: %s", decryptedResponse.Error.Code, decryptedResponse.Error.Message)
	}

	return decryptedResponse.Result, nil
}

// RegisterSecret registers a secret share with the server
func (c *EncryptedOpenADPClient) RegisterSecret(authCode, uid, did, bid string, version, x int, y string, maxGuesses, expiration int, encrypted bool, authData map[string]interface{}) (bool, error) {
	// Server expects: [auth_code, uid, did, bid, version, x, y, max_guesses, expiration] (9 parameters)
	params := []interface{}{authCode, uid, did, bid, version, x, y, maxGuesses, expiration}

	result, err := c.makeRequest("RegisterSecret", params, encrypted, authData)
	if err != nil {
		return false, err
	}

	success, ok := result.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected response type: %T", result)
	}

	return success, nil
}

// RecoverSecret recovers a secret share from the server
func (c *EncryptedOpenADPClient) RecoverSecret(authCode, uid, did, bid, b string, guessNum int, encrypted bool, authData map[string]interface{}) (map[string]interface{}, error) {
	// Server expects: [auth_code, uid, did, bid, b, guess_num] (6 parameters)
	params := []interface{}{authCode, uid, did, bid, b, guessNum}

	result, err := c.makeRequest("RecoverSecret", params, encrypted, authData)
	if err != nil {
		return nil, err
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}

	return resultMap, nil
}

// ListBackups lists all backups for a user
func (c *EncryptedOpenADPClient) ListBackups(uid string, encrypted bool, authData map[string]interface{}) ([]map[string]interface{}, error) {
	// Server expects: [uid] (1 parameter)
	params := []interface{}{uid}

	result, err := c.makeRequest("ListBackups", params, encrypted, authData)
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

// Echo sends an echo message with optional encryption
func (c *EncryptedOpenADPClient) Echo(message string, encrypted bool) (string, error) {
	params := []interface{}{message}

	result, err := c.makeRequest("Echo", params, encrypted, nil)
	if err != nil {
		return "", err
	}

	response, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected response type: %T", result)
	}

	return response, nil
}

// Ping tests connectivity to the server (alias for Echo with "ping" message)
func (c *EncryptedOpenADPClient) Ping() error {
	_, err := c.Echo("ping", false)
	return err
}

// GetServerInfo gets server information
func (c *EncryptedOpenADPClient) GetServerInfo() (map[string]interface{}, error) {
	result, err := c.makeRequest("GetServerInfo", nil, false, nil)
	if err != nil {
		return nil, err
	}

	serverInfo, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}

	return serverInfo, nil
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

// Utility functions

// ParseServerPublicKey parses a base64-encoded server public key
func ParseServerPublicKey(keyB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyB64)
}

// GenerateSessionID generates a unique session identifier
func GenerateSessionID() (string, error) {
	// This would generate a cryptographically secure random session ID
	// For now, use a simple implementation
	return fmt.Sprintf("session_%d", time.Now().UnixNano()), nil
}
