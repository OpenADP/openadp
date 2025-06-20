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

// HasPublicKey returns true if the client has a server public key for encryption
func (c *EncryptedOpenADPClient) HasPublicKey() bool {
	return c.serverPublicKey != nil
}

// makeEncryptedRequest makes an encrypted JSON-RPC request using 2-round Noise-NK protocol
func (c *EncryptedOpenADPClient) makeEncryptedRequest(method string, params interface{}, requestID int, authData map[string]interface{}) (interface{}, error) {
	if c.serverPublicKey == nil {
		return nil, fmt.Errorf("server public key required for encrypted requests")
	}

	// Step 1: Generate session ID
	sessionID := fmt.Sprintf("%d_%d", time.Now().UnixNano(), requestID)

	// Step 2: Create Noise-NK client (initiator)
	noiseClient, err := noise.NewNoiseNK("initiator", nil, c.serverPublicKey, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("failed to create Noise client: %v", err)
	}

	// Step 3: Create client handshake message
	handshakeMsg1, err := noiseClient.WriteHandshakeMessage([]byte("Client handshake"))
	if err != nil {
		return nil, fmt.Errorf("failed to write handshake message: %v", err)
	}

	// Step 4: Round 1 - Send handshake to server
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

	// Step 8: Round 2 - Send encrypted call to server
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

	encryptedRespBytes, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted response: %v", err)
	}

	var encryptedResponse JSONRPCResponse
	if err := json.Unmarshal(encryptedRespBytes, &encryptedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %v", err)
	}

	if encryptedResponse.Error != nil {
		return nil, fmt.Errorf("encrypted call JSON-RPC error %d: %s", encryptedResponse.Error.Code, encryptedResponse.Error.Message)
	}

	// Step 9: Decrypt the response
	encryptedResult, ok := encryptedResponse.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid encrypted response format")
	}

	encryptedDataB64, ok := encryptedResult["data"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted response missing data field")
	}

	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// Decrypt the response
	decryptedResponse, err := noiseClient.Decrypt(encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %v", err)
	}

	// Step 10: Parse the decrypted JSON-RPC response
	var finalResponse JSONRPCResponse
	if err := json.Unmarshal(decryptedResponse, &finalResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted response: %v", err)
	}

	if finalResponse.Error != nil {
		return nil, fmt.Errorf("method error %d: %s", finalResponse.Error.Code, finalResponse.Error.Message)
	}

	return finalResponse.Result, nil
}

// makeRequest makes either encrypted or unencrypted request based on parameters
func (c *EncryptedOpenADPClient) makeRequest(method string, params interface{}, encrypted bool, authData map[string]interface{}) (interface{}, error) {
	c.requestID++

	if encrypted && c.serverPublicKey != nil {
		return c.makeEncryptedRequest(method, params, c.requestID, authData)
	}

	// Fall back to unencrypted request
	response, err := c.OpenADPClient.makeRequest(method, params)
	if err != nil {
		return nil, err
	}

	return response.Result, nil
}

// RegisterSecret registers a secret with optional encryption
func (c *EncryptedOpenADPClient) RegisterSecret(authCode, uid, did, bid string, version, x int, y string, maxGuesses, expiration int, encrypted bool, authData map[string]interface{}) (bool, error) {
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

// RecoverSecret recovers a secret with optional encryption
func (c *EncryptedOpenADPClient) RecoverSecret(authCode, did, bid, b string, guessNum int, encrypted bool, authData map[string]interface{}) (map[string]interface{}, error) {
	params := []interface{}{authCode, did, bid, b, guessNum}

	result, err := c.makeRequest("RecoverSecret", params, encrypted, authData)
	if err != nil {
		return nil, err
	}

	response, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}

	return response, nil
}

// ListBackups lists backups for a user with auth code verification
func (c *EncryptedOpenADPClient) ListBackups(uid, authCode string, encrypted bool, authData map[string]interface{}) ([]map[string]interface{}, error) {
	params := []interface{}{uid, authCode}

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

// ParseServerPublicKey parses a base64-encoded server public key
func ParseServerPublicKey(keyB64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(keyB64)
}
