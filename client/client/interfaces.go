package client

import "fmt"

// StandardOpenADPClientInterface defines the standardized interface for OpenADP client operations
// This interface is designed to be easily implementable across different programming languages
// Legacy clients can implement this via wrapper methods (e.g., RegisterSecretStandardized)
type StandardOpenADPClientInterface interface {
	// Core Operations - Standardized
	RegisterSecretStandardized(request *RegisterSecretRequest) (*RegisterSecretResponse, error)
	RecoverSecretStandardized(request *RecoverSecretRequest) (*RecoverSecretResponse, error)
	ListBackupsStandardized(request *ListBackupsRequest) (*ListBackupsResponse, error)

	// Utility Operations - Standardized
	GetServerInfoStandardized() (*ServerInfoResponse, error)

	// Connection Management
	TestConnection() error
	GetServerURL() string
	SupportsEncryption() bool
}

// StandardMultiServerClientInterface defines interface for managing multiple servers
type StandardMultiServerClientInterface interface {
	StandardOpenADPClientInterface

	// Multi-server Operations
	GetLiveServerCount() int
	GetLiveServerURLs() []string
	RefreshServers() error

	// Server Selection Strategy
	SetServerSelectionStrategy(strategy ServerSelectionStrategy)
}

// ServerSelectionStrategy defines how to choose servers for operations
type ServerSelectionStrategy int

const (
	FirstAvailable ServerSelectionStrategy = iota
	RoundRobin
	Random
	LowestLatency
)

// Request/Response Types - Designed for easy JSON serialization across languages

type RegisterSecretRequest struct {
	AuthCode   string                 `json:"auth_code"`
	UID        string                 `json:"uid"`
	DID        string                 `json:"did"`
	BID        string                 `json:"bid"`
	Version    int                    `json:"version"`
	X          int                    `json:"x"`
	Y          string                 `json:"y"` // Base64 encoded point
	MaxGuesses int                    `json:"max_guesses"`
	Expiration int                    `json:"expiration"`
	Encrypted  bool                   `json:"encrypted,omitempty"`
	AuthData   map[string]interface{} `json:"auth_data,omitempty"`
}

type RegisterSecretResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type RecoverSecretRequest struct {
	AuthCode  string                 `json:"auth_code"`
	DID       string                 `json:"did"`
	BID       string                 `json:"bid"`
	B         string                 `json:"b"` // Base64 encoded point
	GuessNum  int                    `json:"guess_num"`
	Encrypted bool                   `json:"encrypted,omitempty"`
	AuthData  map[string]interface{} `json:"auth_data,omitempty"`
}

type RecoverSecretResponse struct {
	Version    int    `json:"version"`
	X          int    `json:"x"`
	SiB        string `json:"si_b"` // Base64 encoded point
	NumGuesses int    `json:"num_guesses"`
	MaxGuesses int    `json:"max_guesses"`
	Expiration int    `json:"expiration"`
}

type ListBackupsRequest struct {
	UID       string                 `json:"uid"`
	AuthCode  string                 `json:"auth_code"`
	Encrypted bool                   `json:"encrypted,omitempty"`
	AuthData  map[string]interface{} `json:"auth_data,omitempty"`
}

type ListBackupsResponse struct {
	Backups []BackupInfo `json:"backups"`
}

type BackupInfo struct {
	UID        string `json:"uid"`
	BID        string `json:"bid"`
	Version    int    `json:"version"`
	NumGuesses int    `json:"num_guesses"`
	MaxGuesses int    `json:"max_guesses"`
	Expiration int    `json:"expiration"`
}

type ServerInfoResponse struct {
	ServerVersion    string                 `json:"server_version"`
	NoiseNKPublicKey string                 `json:"noise_nk_public_key,omitempty"`
	SupportedMethods []string               `json:"supported_methods"`
	MaxRequestSize   int                    `json:"max_request_size,omitempty"`
	RateLimits       map[string]interface{} `json:"rate_limits,omitempty"`
}

// ClientConfig holds configuration for client creation
type ClientConfig struct {
	ServerURL        string   `json:"server_url,omitempty"`
	ServerURLs       []string `json:"server_urls,omitempty"`
	RegistryURL      string   `json:"registry_url,omitempty"`
	PublicKey        string   `json:"public_key,omitempty"` // Base64 encoded
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
	MaxWorkers       int      `json:"max_workers,omitempty"`
	EnableEncryption bool     `json:"enable_encryption,omitempty"`
	UserAgent        string   `json:"user_agent,omitempty"`
}

// Error types for consistent error handling across languages
type OpenADPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *OpenADPError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("OpenADP Error %d: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("OpenADP Error %d: %s", e.Code, e.Message)
}

// Common error codes
const (
	ErrorCodeNetworkFailure       = 1001
	ErrorCodeAuthenticationFailed = 1002
	ErrorCodeInvalidRequest       = 1003
	ErrorCodeServerError          = 1004
	ErrorCodeEncryptionFailed     = 1005
	ErrorCodeNoLiveServers        = 1006
	ErrorCodeInvalidResponse      = 1007
)
