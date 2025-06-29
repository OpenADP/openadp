// Package main implements a JSON-RPC 2.0 server for OpenADP operations.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/mux"

	"github.com/openadp/ocrypt/common"
	"github.com/openadp/server/database"
	"github.com/openadp/server/server"
)

const (
	version = "1.0.0"
	banner  = `
 ██████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████║██║  ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══██║██║  ██║██╔═══╝ 
╚██████╔╝██║     ███████╗██║ ╚████║██║  ██║██████╔╝██║     
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═╝     
                                                            
OpenADP JSON-RPC Server v%s
`
)

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// RequestContext tracks whether a request came through encrypted channel
type RequestContext struct {
	IsEncrypted bool
	SessionID   string
}

// Server represents the OpenADP JSON-RPC server
type Server struct {
	db             *database.Database
	serverKey      []byte
	authEnabled    bool
	port           int
	dbPath         string
	monitoring     *server.MonitoringTracker
	sessionManager *server.NoiseSessionManager // Add session manager
}

// NewServer creates a new OpenADP server instance
func NewServer(dbPath string, port int, authEnabled bool) (*Server, error) {
	// Initialize database
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	// Load or generate server key pair
	serverKey, privateKey, err := loadOrGenerateServerKeyPair(db)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server key: %v", err)
	}

	// Construct DHKey from the keys we just loaded/generated
	var dhKey *noise.DHKey
	if len(privateKey) == 32 && len(serverKey) == 32 {
		dhKey = &noise.DHKey{
			Private: make([]byte, 32),
			Public:  make([]byte, 32),
		}
		copy(dhKey.Private, privateKey)
		copy(dhKey.Public, serverKey)
	} else {
		return nil, fmt.Errorf("invalid key lengths: private=%d, public=%d", len(privateKey), len(serverKey))
	}

	return &Server{
		db:             db,
		serverKey:      serverKey,
		authEnabled:    authEnabled,
		port:           port,
		dbPath:         dbPath,
		monitoring:     server.NewMonitoringTracker(),
		sessionManager: server.NewNoiseSessionManager(dhKey),
	}, nil
}

// loadOrGenerateServerKeyPair loads existing server key pair or generates a new one
// Returns both public and private keys to avoid database reload issues
func loadOrGenerateServerKeyPair(db *database.Database) ([]byte, []byte, error) {
	// Try to load existing keys
	publicKeyData, err := db.GetServerConfig("server_public_key")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server public key: %v", err)
	}

	privateKeyData, err := db.GetServerConfig("server_private_key")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get server private key: %v", err)
	}

	// If both keys exist and are valid, use them
	if publicKeyData != nil && privateKeyData != nil && len(publicKeyData) == 32 && len(privateKeyData) == 32 {
		log.Println("Loaded existing server key pair from database")
		return publicKeyData, privateKeyData, nil
	}

	// Generate new key pair
	log.Println("Generating new server key pair...")
	privateKey, publicKey, err := common.X25519GenerateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Store the public key in database
	err = db.SetServerConfig("server_public_key", publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store server public key: %v", err)
	}

	// Store private key for future use
	err = db.SetServerConfig("server_private_key", privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store server private key: %v", err)
	}

	log.Println("Generated and stored new server key pair")
	return publicKey, privateKey, nil
}

// handleJSONRPC handles JSON-RPC 2.0 requests
func (s *Server) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		s.monitoring.RecordError()
		return
	}

	// Parse JSON-RPC request
	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    -32700,
				Message: "Parse error",
			},
			ID: nil,
		}
		json.NewEncoder(w).Encode(response)
		s.monitoring.RecordError()
		return
	}

	// Route to appropriate method based on 2-round Noise-NK approach
	var result interface{}
	var err error

	switch req.Method {
	case "noise_handshake":
		// Round 1: Establish Noise-NK session
		result, err = s.handleNoiseHandshake(req.Params)
	case "encrypted_call":
		// Round 2: Process encrypted request and return encrypted response
		result, err = s.handleEncryptedCall(req.Params)
	default:
		// Regular unencrypted methods
		result, err = s.routeMethodWithContext(req.Method, req.Params, &RequestContext{
			IsEncrypted: false,
			SessionID:   "",
		})
	}

	// Build response
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	if err != nil {
		response.Error = &JSONRPCError{
			Code:    -32603,
			Message: err.Error(),
		}
		s.monitoring.RecordError()
	} else {
		response.Result = result
		// Record successful request with response time
		responseTime := float64(time.Since(startTime).Nanoseconds()) / 1000000.0 // Convert to milliseconds
		s.monitoring.RecordRequest(responseTime)
	}

	json.NewEncoder(w).Encode(response)
}

// routeMethodWithContext routes JSON-RPC method calls with request context
func (s *Server) routeMethodWithContext(method string, params []interface{}, ctx *RequestContext) (interface{}, error) {
	switch method {
	case "Echo":
		return s.handleEcho(params)
	case "GetServerInfo":
		return s.handleGetServerInfo(params)
	case "RegisterSecret":
		// Enforce encryption for RegisterSecret
		if !ctx.IsEncrypted {
			return nil, fmt.Errorf("RegisterSecret requires Noise-NK encryption")
		}
		return s.handleRegisterSecret(params)
	case "RecoverSecret":
		// Enforce encryption for RecoverSecret
		if !ctx.IsEncrypted {
			return nil, fmt.Errorf("RecoverSecret requires Noise-NK encryption")
		}
		return s.handleRecoverSecret(params)
	case "ListBackups":
		return s.handleListBackups(params)
	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

// handleEcho handles the Echo method
func (s *Server) handleEcho(params []interface{}) (interface{}, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("Echo requires exactly 1 parameter")
	}

	message, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("Echo parameter must be a string")
	}

	return server.Echo(message), nil
}

// handleGetServerInfo handles the GetServerInfo method
func (s *Server) handleGetServerInfo(params []interface{}) (interface{}, error) {
	// Use the session manager's public key for consistency with handshakes
	sessionManagerKey := s.sessionManager.GetServerPublicKey()
	return server.GetServerInfo(version, sessionManagerKey, s.monitoring), nil
}

// handleRegisterSecret handles the RegisterSecret method
func (s *Server) handleRegisterSecret(params []interface{}) (interface{}, error) {
	if len(params) != 9 {
		return nil, fmt.Errorf("RegisterSecret requires exactly 9 parameters")
	}

	// Parse parameters: [auth_code, uid, did, bid, version, x, y, max_guesses, expiration]
	authCode, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("auth_code must be a string")
	}

	uid, ok := params[1].(string)
	if !ok {
		return nil, fmt.Errorf("uid must be a string")
	}

	did, ok := params[2].(string)
	if !ok {
		return nil, fmt.Errorf("did must be a string")
	}

	bid, ok := params[3].(string)
	if !ok {
		return nil, fmt.Errorf("bid must be a string")
	}

	versionFloat, ok := params[4].(float64)
	if !ok {
		return nil, fmt.Errorf("version must be a number")
	}
	version := int(versionFloat)

	xFloat, ok := params[5].(float64)
	if !ok {
		return nil, fmt.Errorf("x must be a number")
	}
	x := int(xFloat)

	yStr, ok := params[6].(string)
	if !ok {
		return nil, fmt.Errorf("y must be a string")
	}

	// Y coordinate must be base64-encoded 32-byte little-endian format (per API spec)
	var y []byte
	var err error
	y, err = base64.StdEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: must be valid base64 encoding")
	}

	// Validate that we got exactly 32 bytes (per API spec)
	if len(y) != 32 {
		return nil, fmt.Errorf("invalid y coordinate: base64 must decode to exactly 32 bytes, got %d", len(y))
	}

	// Validate that the decoded value is within valid range (< Q, the group order)
	// Note: y is in little-endian format (per API spec), so we need to convert it
	// to big-endian for SetBytes validation by reversing the bytes
	yBytes := make([]byte, len(y))
	copy(yBytes, y)
	// Reverse bytes to convert from little-endian to big-endian for SetBytes
	for i, j := 0, len(yBytes)-1; i < j; i, j = i+1, j-1 {
		yBytes[i], yBytes[j] = yBytes[j], yBytes[i]
	}
	yInt := new(big.Int).SetBytes(yBytes)
	if yInt.Cmp(common.Q) >= 0 {
		return nil, fmt.Errorf("invalid y coordinate: value must be less than group order Q")
	}

	maxGuessesFloat, ok := params[7].(float64)
	if !ok {
		return nil, fmt.Errorf("max_guesses must be a number")
	}
	maxGuesses := int(maxGuessesFloat)

	expirationFloat, ok := params[8].(float64)
	if !ok {
		return nil, fmt.Errorf("expiration must be a number")
	}
	expiration := int64(expirationFloat)

	// Debug: Print what we're storing
	// Convert little-endian bytes back to correct decimal value for logging
	yInt.SetBytes([]byte{}) // Reset the existing yInt
	yBytes = make([]byte, len(y))
	copy(yBytes, y)
	// Reverse bytes to convert from little-endian to big-endian for SetBytes
	for i, j := 0, len(yBytes)-1; i < j; i, j = i+1, j-1 {
		yBytes[i], yBytes[j] = yBytes[j], yBytes[i]
	}
	yInt.SetBytes(yBytes)
	fmt.Printf("SERVER %d STORING: uid=%s, did=%s, bid=%s, x=%d, y=%s (hex: %x)\n",
		s.port, uid, did, bid, x, yInt.String(), y)

	// Register the secret
	err = server.RegisterSecret(s.db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		return nil, err
	}

	return true, nil
}

// handleRecoverSecret handles the RecoverSecret method
func (s *Server) handleRecoverSecret(params []interface{}) (interface{}, error) {
	if len(params) != 6 {
		return nil, fmt.Errorf("RecoverSecret requires exactly 6 parameters")
	}

	// Parse parameters: [auth_code, uid, did, bid, b, guess_num]
	authCode, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("auth_code must be a string")
	}

	uid, ok := params[1].(string)
	if !ok {
		return nil, fmt.Errorf("uid must be a string")
	}

	did, ok := params[2].(string)
	if !ok {
		return nil, fmt.Errorf("did must be a string")
	}

	bid, ok := params[3].(string)
	if !ok {
		return nil, fmt.Errorf("bid must be a string")
	}

	// Parse point B (expecting base64 encoded compressed point only)
	bStr, ok := params[4].(string)
	if !ok {
		return nil, fmt.Errorf("b must be a base64-encoded compressed point string")
	}

	bBytes, err := base64.StdEncoding.DecodeString(bStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 b parameter: %v", err)
	}

	// Decompress point
	b4D, err := common.PointDecompress(bBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid compressed point b: %v", err)
	}
	b := common.Unexpand(b4D)

	guessNumFloat, ok := params[5].(float64)
	if !ok {
		return nil, fmt.Errorf("guess_num must be a number")
	}
	guessNum := int(guessNumFloat)

	// Recover the secret using auth code and primary key
	response, err := server.RecoverSecretWithAuthCode(s.db, authCode, uid, did, bid, b, guessNum)
	if err != nil {
		return nil, err
	}

	// Convert response to JSON-compatible format
	// Create Point4D from Point2D for compression
	siB4D := &common.Point4D{
		X: new(big.Int).Set(response.SiB.X),
		Y: new(big.Int).Set(response.SiB.Y),
		Z: big.NewInt(1),
		T: new(big.Int).Mul(response.SiB.X, response.SiB.Y),
	}
	siB4D.T.Mod(siB4D.T, common.P)

	return map[string]interface{}{
		"version":     response.Version,
		"x":           response.X,
		"si_b":        base64.StdEncoding.EncodeToString(common.PointCompress(siB4D)),
		"num_guesses": response.NumGuesses,
		"max_guesses": response.MaxGuesses,
		"expiration":  response.Expiration,
	}, nil
}

// handleListBackups handles the ListBackups method
func (s *Server) handleListBackups(params []interface{}) (interface{}, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("ListBackups requires exactly 1 parameter: uid")
	}

	uid, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("uid must be a string")
	}

	// Get all backups for this user using the proper ListBackups function
	backups, err := server.ListBackups(s.db, uid)
	if err != nil {
		return nil, err
	}

	// Return proper JSON object format as documented in SERVER_API.md
	return backups, nil
}

// handleNoiseHandshake handles Round 1: Noise-NK handshake establishment
func (s *Server) handleNoiseHandshake(params []interface{}) (interface{}, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("noise_handshake requires exactly 1 parameter")
	}

	// Parse params which should be {"session": "sessionId", "message": "base64_msg"}
	paramsObj, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("noise_handshake params must be an object")
	}

	sessionID, ok := paramsObj["session"].(string)
	if !ok {
		return nil, fmt.Errorf("noise_handshake requires 'session' field")
	}

	msgB64, ok := paramsObj["message"].(string)
	if !ok {
		return nil, fmt.Errorf("noise_handshake requires 'message' field")
	}

	// Decode handshake message
	handshakeMsg, err := base64.StdEncoding.DecodeString(msgB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 handshake message: %v", err)
	}

	// Start handshake - this processes client's message and returns server response
	serverHandshakeResponse, err := s.sessionManager.StartHandshake(sessionID, handshakeMsg)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %v", err)
	}

	// Return server's handshake response
	return map[string]interface{}{
		"message": base64.StdEncoding.EncodeToString(serverHandshakeResponse),
	}, nil
}

// handleEncryptedCall handles Round 2: Encrypted method call
func (s *Server) handleEncryptedCall(params []interface{}) (interface{}, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("encrypted_call requires exactly 1 parameter")
	}

	// Parse params which should be {"session": "sessionId", "data": "base64_encrypted_data"}
	paramsObj, ok := params[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("encrypted_call params must be an object")
	}

	sessionID, ok := paramsObj["session"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted_call requires 'session' field")
	}

	dataB64, ok := paramsObj["data"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted_call requires 'data' field")
	}

	// Decode encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encrypted data: %v", err)
	}

	// Decrypt the call
	decryptedCall, err := s.sessionManager.DecryptCall(sessionID, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Extract method and params from decrypted call
	method, ok := decryptedCall["method"].(string)
	if !ok {
		return nil, fmt.Errorf("decrypted call missing method")
	}

	callParams, ok := decryptedCall["params"].([]interface{})
	if !ok {
		// params might be nil or not an array
		callParams = []interface{}{}
	}

	// Route the decrypted method call (mark as encrypted)
	result, err := s.routeMethodWithContext(method, callParams, &RequestContext{
		IsEncrypted: true,
		SessionID:   sessionID,
	})

	// Prepare response for encryption
	responseDict := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      decryptedCall["id"],
	}

	if err != nil {
		responseDict["error"] = map[string]interface{}{
			"code":    -32603,
			"message": err.Error(),
		}
	} else {
		responseDict["result"] = result
	}

	// Encrypt the response
	encryptedResponse, err := s.sessionManager.EncryptResponse(sessionID, responseDict)
	if err != nil {
		return nil, fmt.Errorf("response encryption failed: %v", err)
	}

	// Return encrypted response
	return map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString(encryptedResponse),
	}, nil
}

// Start starts the JSON-RPC server
func (s *Server) Start() error {
	router := mux.NewRouter()
	router.HandleFunc("/", s.handleJSONRPC).Methods("POST", "OPTIONS")

	// Add health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"version": version,
		})
	}).Methods("GET")

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Starting OpenADP JSON-RPC server on %s", addr)
	log.Printf("Database: %s", s.dbPath)
	log.Printf("Authentication: %v", s.authEnabled)
	log.Printf("Server public key: %s", base64.StdEncoding.EncodeToString(s.serverKey)[:32]+"...")

	return http.ListenAndServe(addr, router)
}

// Close closes the server and database connections
func (s *Server) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func main() {
	var (
		port        = flag.Int("port", 8080, "Port to listen on")
		dbPath      = flag.String("db", "openadp.db", "Path to SQLite database file")
		authEnabled = flag.Bool("auth", true, "Enable authentication")
		debugMode   = flag.Bool("debug", false, "Enable debug mode (deterministic ephemeral keys)")
		showVersion = flag.Bool("version", false, "Show version information")
		showHelp    = flag.Bool("help", false, "Show help information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP JSON-RPC Server v%s\n", version)
		return
	}

	if *showHelp {
		fmt.Printf(banner, version)
		fmt.Println("\nOpenADP JSON-RPC Server")
		fmt.Println("=======================")
		fmt.Println("\nUSAGE:")
		fmt.Println("    openadp-server [OPTIONS]")
		fmt.Println("\nOPTIONS:")
		flag.PrintDefaults()
		fmt.Println("\nEXAMPLES:")
		fmt.Println("    # Start server on default port")
		fmt.Println("    openadp-server")
		fmt.Println("")
		fmt.Println("    # Start on custom port with custom database")
		fmt.Println("    openadp-server -port 9090 -db /path/to/db.sqlite")
		fmt.Println("")
		fmt.Println("    # Start in debug mode")
		fmt.Println("    openadp-server --debug")
		return
	}

	// Override with environment variables if set
	if envPort := os.Getenv("OPENADP_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
	}
	if envDB := os.Getenv("OPENADP_DB"); envDB != "" {
		*dbPath = envDB
	}
	if envAuth := os.Getenv("OPENADP_AUTH"); envAuth != "" {
		*authEnabled = envAuth == "true" || envAuth == "1"
	}
	if envDebug := os.Getenv("OPENADP_DEBUG"); envDebug != "" {
		*debugMode = envDebug == "true" || envDebug == "1"
	}

	fmt.Printf(banner, version)

	// Set debug mode if requested
	if *debugMode {
		log.Printf("🐛 Debug mode enabled - using deterministic ephemeral keys")
		server.SetDebugMode(true)
	}

	// Create and start server
	srv, err := NewServer(*dbPath, *port, *authEnabled)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Close()

	// Start server
	log.Fatal(srv.Start())
}
