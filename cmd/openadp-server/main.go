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

	"github.com/gorilla/mux"

	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/database"
	"github.com/openadp/openadp/pkg/server"
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

// Server represents the OpenADP JSON-RPC server
type Server struct {
	db          *database.Database
	serverKey   []byte
	authEnabled bool
	port        int
	dbPath      string
}

// NewServer creates a new OpenADP server instance
func NewServer(dbPath string, port int, authEnabled bool) (*Server, error) {
	// Initialize database
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	// Load or generate server key
	serverKey, err := loadOrGenerateServerKey(db)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server key: %v", err)
	}

	return &Server{
		db:          db,
		serverKey:   serverKey,
		authEnabled: authEnabled,
		port:        port,
		dbPath:      dbPath,
	}, nil
}

// loadOrGenerateServerKey loads existing server key or generates a new one
func loadOrGenerateServerKey(db *database.Database) ([]byte, error) {
	// Try to load existing key
	keyData, err := db.GetServerConfig("server_public_key")
	if err != nil {
		return nil, fmt.Errorf("failed to get server config: %v", err)
	}

	if keyData != nil {
		log.Println("Loaded existing server key from database")
		return keyData, nil
	}

	// Generate new key pair
	log.Println("Generating new server key pair...")
	privateKey, publicKey, err := crypto.X25519GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Store the public key in database
	err = db.SetServerConfig("server_public_key", publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to store server key: %v", err)
	}

	// Also store private key for future use
	err = db.SetServerConfig("server_private_key", privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to store private key: %v", err)
	}

	log.Println("Generated and stored new server key pair")
	return publicKey, nil
}

// handleJSONRPC handles JSON-RPC 2.0 requests
func (s *Server) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
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
		return
	}

	// Route to appropriate method
	result, err := s.routeMethod(req.Method, req.Params)

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
	} else {
		response.Result = result
	}

	json.NewEncoder(w).Encode(response)
}

// routeMethod routes JSON-RPC method calls to appropriate handlers
func (s *Server) routeMethod(method string, params []interface{}) (interface{}, error) {
	switch method {
	case "Echo":
		return s.handleEcho(params)
	case "GetServerInfo":
		return s.handleGetServerInfo(params)
	case "RegisterSecret":
		return s.handleRegisterSecret(params)
	case "RecoverSecret":
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
	return server.GetServerInfo(version, s.serverKey), nil
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

	// Try to decode Y coordinate - support both decimal string and base64 formats
	var y []byte
	var err error

	// First try parsing as decimal integer (openadp.org compatible format)
	// Check if the string looks like a decimal number (all digits)
	isDecimal := true
	for _, b := range []byte(yStr) {
		if b < '0' || b > '9' {
			isDecimal = false
			break
		}
	}

	if isDecimal {
		yInt := new(big.Int)
		yInt, ok := yInt.SetString(yStr, 10)
		if ok {
			// Validate that Y is within valid range (< P, the prime modulus)
			if yInt.Cmp(crypto.P) >= 0 {
				return nil, fmt.Errorf("invalid y coordinate: value must be less than prime modulus P")
			}

			// Convert big integer to little-endian bytes (to match Python server)
			// Use fixed 32-byte length like Python server: y_int.to_bytes(32, "little")
			y = make([]byte, 32)

			// Get big-endian bytes and reverse to little-endian
			bigEndianBytes := yInt.Bytes()

			// Copy in reverse order to convert big-endian to little-endian
			// Start from the least significant byte (rightmost in big-endian)
			for i, b := range bigEndianBytes {
				if len(bigEndianBytes)-1-i < 32 {
					y[len(bigEndianBytes)-1-i] = b
				}
			}
		} else {
			isDecimal = false
		}
	}

	// If decimal parsing failed or string doesn't look decimal, try base64
	if !isDecimal {
		y, err = base64.StdEncoding.DecodeString(yStr)
		if err != nil {
			return nil, fmt.Errorf("invalid y coordinate: not valid decimal integer or base64")
		}

		// Also validate base64 decoded values
		yInt := new(big.Int).SetBytes(y)
		if yInt.Cmp(crypto.P) >= 0 {
			return nil, fmt.Errorf("invalid y coordinate: value must be less than prime modulus P")
		}
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
	yInt := new(big.Int)
	yInt.SetBytes(y)
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
	if len(params) != 5 {
		return nil, fmt.Errorf("RecoverSecret requires exactly 5 parameters")
	}

	// Parse parameters: [auth_code, did, bid, b, guess_num]
	authCode, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("auth_code must be a string")
	}

	did, ok := params[1].(string)
	if !ok {
		return nil, fmt.Errorf("did must be a string")
	}

	bid, ok := params[2].(string)
	if !ok {
		return nil, fmt.Errorf("bid must be a string")
	}

	// Parse point B (expecting base64 encoded compressed point only)
	bStr, ok := params[3].(string)
	if !ok {
		return nil, fmt.Errorf("b must be a base64-encoded compressed point string")
	}

	bBytes, err := base64.StdEncoding.DecodeString(bStr)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 b parameter: %v", err)
	}

	// Decompress point
	b4D, err := crypto.PointDecompress(bBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid compressed point b: %v", err)
	}
	b := crypto.Unexpand(b4D)

	guessNumFloat, ok := params[4].(float64)
	if !ok {
		return nil, fmt.Errorf("guess_num must be a number")
	}
	guessNum := int(guessNumFloat)

	// Debug: Print what we're about to recover
	fmt.Printf("SERVER %d RECOVERING: did=%s, bid=%s, guess_num=%d\n",
		s.port, did, bid, guessNum)

	// Recover the secret using auth code
	response, err := server.RecoverSecretByAuthCode(s.db, authCode, did, bid, b, guessNum)
	if err != nil {
		return nil, err
	}

	// Debug: Print what we recovered
	fmt.Printf("SERVER %d RECOVERED: x=%d, si_b=(%s, %s)\n",
		s.port, response.X, response.SiB.X.String(), response.SiB.Y.String())

	// Convert response to JSON-compatible format
	// Create Point4D from Point2D for compression
	siB4D := &crypto.Point4D{
		X: new(big.Int).Set(response.SiB.X),
		Y: new(big.Int).Set(response.SiB.Y),
		Z: big.NewInt(1),
		T: new(big.Int).Mul(response.SiB.X, response.SiB.Y),
	}

	return map[string]interface{}{
		"version":     response.Version,
		"x":           response.X,
		"si_b":        base64.StdEncoding.EncodeToString(crypto.PointCompress(siB4D)),
		"num_guesses": response.NumGuesses,
		"max_guesses": response.MaxGuesses,
		"expiration":  response.Expiration,
	}, nil
}

// handleListBackups handles the ListBackups method
func (s *Server) handleListBackups(params []interface{}) (interface{}, error) {
	if len(params) != 1 {
		return nil, fmt.Errorf("ListBackups requires exactly 1 parameter")
	}

	authCode, ok := params[0].(string)
	if !ok {
		return nil, fmt.Errorf("auth_code must be a string")
	}

	// List backups using auth code
	backups, err := server.ListBackupsByAuthCode(s.db, authCode)
	if err != nil {
		return nil, err
	}

	return backups, nil
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

	fmt.Printf(banner, version)

	// Create and start server
	srv, err := NewServer(*dbPath, *port, *authEnabled)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Close()

	// Start server
	log.Fatal(srv.Start())
}
