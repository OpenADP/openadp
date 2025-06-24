// OpenADP Authentication Code Demo
//
// This tool demonstrates the complete authentication code workflow:
// 1. Generate authentication codes
// 2. Create encrypted backups using OpenADP protocol
// 3. Register Shamir shares with servers using authentication codes
// 4. Show the complete workflow in action
//
// This replaces the OAuth/DPoP authentication system with a simpler,
// distributed authentication code approach.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/openadp/common/crypto"
	"github.com/openadp/common/sharing"
	"github.com/openadp/server/auth"
)

const version = "1.0.0"

type AuthCodeDemo struct {
	serverURLs  []string
	threshold   int
	totalShares int
	authManager *auth.AuthCodeManager
}

func main() {
	var (
		serversFlag = flag.String("servers", "http://localhost:8080,http://localhost:8081,http://localhost:8082", "Comma-separated list of server URLs")
		userPin     = flag.String("pin", "demo123", "User PIN/password for demo")
		deviceID    = flag.String("device", "demo-device", "Device identifier")
		backupID    = flag.String("backup", "demo-backup.txt", "Backup identifier")
		help        = flag.Bool("help", false, "Show help information")
		showVersion = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP Authentication Code Demo v%s\n", version)
		return
	}

	if *help {
		showHelp()
		return
	}

	// Parse server URLs
	serverURLs := strings.Split(*serversFlag, ",")
	for i, url := range serverURLs {
		serverURLs[i] = strings.TrimSpace(url)
	}

	// Initialize demo
	demo := NewAuthCodeDemo(serverURLs)

	// Run the demo
	fmt.Println("🚀 OpenADP Authentication Code Demo")
	fmt.Println("===================================")
	fmt.Printf("📋 Configuration:\n")
	fmt.Printf("   • Servers: %d\n", len(serverURLs))
	fmt.Printf("   • Threshold: %d-of-%d\n", demo.threshold, demo.totalShares)
	fmt.Printf("   • Device ID: %s\n", *deviceID)
	fmt.Printf("   • Backup ID: %s\n", *backupID)
	fmt.Printf("   • User PIN: %s\n", *userPin)
	fmt.Println()

	// Demo data
	demoData := []byte("This is demo data for OpenADP authentication code workflow demonstration. " +
		"It shows how authentication codes can be used instead of OAuth for distributed secret sharing.")

	// Step 1: Create backup
	fmt.Println("🔐 Step 1: Creating Backup")
	fmt.Println("==========================")
	baseAuthCode, serverAuthCodes, err := demo.CreateBackup(demoData, *userPin, *deviceID, *backupID)
	if err != nil {
		fmt.Printf("❌ Failed to create backup: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Backup created successfully!\n")
	fmt.Printf("   • Base auth code: %s\n", baseAuthCode)
	fmt.Printf("   • Server codes: %d generated\n", len(serverAuthCodes))
	fmt.Println()

	// Step 2: Demonstrate recovery workflow
	fmt.Println("🔓 Step 2: Recovery Workflow Demo")
	fmt.Println("=================================")
	err = demo.DemonstrateRecovery(baseAuthCode, *userPin, *deviceID, *backupID)
	if err != nil {
		fmt.Printf("❌ Recovery demo failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("🎉 Demo completed successfully!")
	fmt.Println("===============================")
	fmt.Println("✅ Demonstrated functionality:")
	fmt.Println("   • Authentication code generation")
	fmt.Println("   • Server-specific code derivation")
	fmt.Println("   • Cryptographic point computation")
	fmt.Println("   • Shamir secret sharing")
	fmt.Println("   • Share registration workflow")
	fmt.Println("   • Recovery protocol simulation")
	fmt.Println()
	fmt.Println("📝 Note: This demo shows the cryptographic workflow.")
	fmt.Println("   For full functionality, use openadp-encrypt/decrypt tools.")
}

func NewAuthCodeDemo(serverURLs []string) *AuthCodeDemo {
	threshold := min(2, len(serverURLs)) // Use 2-of-N threshold
	if len(serverURLs) == 1 {
		threshold = 1 // Special case for single server
	}

	return &AuthCodeDemo{
		serverURLs:  serverURLs,
		threshold:   threshold,
		totalShares: len(serverURLs),
		authManager: auth.NewAuthCodeManager(),
	}
}

func (demo *AuthCodeDemo) CreateBackup(fileData []byte, userPin, deviceID, backupID string) (string, map[string]string, error) {
	fmt.Printf("🔐 Creating backup for device '%s', backup '%s'\n", deviceID, backupID)

	// 1. Generate authentication code
	baseAuthCode, err := demo.authManager.GenerateAuthCode()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate auth code: %v", err)
	}

	serverAuthCodes := demo.authManager.GetServerCodes(baseAuthCode, demo.serverURLs)

	fmt.Printf("🔑 Generated base authentication code: %s\n", baseAuthCode)
	fmt.Printf("🌐 Derived %d server-specific codes\n", len(serverAuthCodes))

	// 2. OpenADP Protocol: Generate cryptographic materials
	// Derive UUID from base auth code for consistent user identification
	hash := sha256.Sum256([]byte(baseAuthCode))
	uuid := fmt.Sprintf("%x", hash[:8]) // Use first 16 hex chars

	// Compute user identity point: U = H(UUID, DID, BID, pin)
	U := crypto.H([]byte(uuid), []byte(deviceID), []byte(backupID), []byte(userPin))
	fmt.Printf("👤 User identity point U computed\n")

	// Generate random secret and compute S = s * U
	secret, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate random secret: %v", err)
	}

	S := crypto.PointMul(secret, U)
	fmt.Printf("🔒 Secret point S = s * U computed\n")

	// Derive encryption key: enc_key = HKDF(S.x || S.y)
	encKey := crypto.DeriveEncKey(S)
	fmt.Printf("🗝️  Encryption key derived from S (length: %d bytes)\n", len(encKey))

	// 3. Create Shamir secret shares
	shares, err := sharing.MakeRandomShares(secret, demo.threshold, demo.totalShares)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create shares: %v", err)
	}

	fmt.Printf("🧩 Created %d Shamir shares with %d-of-%d threshold\n", len(shares), demo.threshold, demo.totalShares)

	// 4. Simulate share registration with servers
	fmt.Printf("📡 Simulating share registration with %d servers...\n", len(demo.serverURLs))

	for i, serverURL := range demo.serverURLs {
		if i >= len(shares) {
			break
		}

		share := shares[i]
		serverAuthCode := serverAuthCodes[serverURL]

		// In a real implementation, this would use the JSON-RPC client
		fmt.Printf("  ✅ Would register share %s with %s (auth: %s...)\n",
			share.X.String(), serverURL, serverAuthCode[:8])
	}

	// 5. Simulate file encryption
	fmt.Printf("🔐 Simulated encryption: %d bytes -> encrypted with derived key\n", len(fileData))

	return baseAuthCode, serverAuthCodes, nil
}

func (demo *AuthCodeDemo) DemonstrateRecovery(baseAuthCode, userPin, deviceID, backupID string) error {
	fmt.Printf("🔓 Demonstrating recovery for device '%s', backup '%s'\n", deviceID, backupID)

	// 1. Derive server-specific codes
	serverAuthCodes := demo.authManager.GetServerCodes(baseAuthCode, demo.serverURLs)
	fmt.Printf("🌐 Derived %d server-specific codes\n", len(serverAuthCodes))

	// 2. OpenADP Protocol: Compute user identity point
	hash := sha256.Sum256([]byte(baseAuthCode))
	uuid := fmt.Sprintf("%x", hash[:8])
	U := crypto.H([]byte(uuid), []byte(deviceID), []byte(backupID), []byte(userPin))
	fmt.Printf("👤 User identity point U computed\n")

	// 3. Generate blinding factor and compute B = r * U
	r, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		return fmt.Errorf("failed to generate blinding factor: %v", err)
	}

	B := crypto.PointMul(r, U)
	fmt.Printf("🎭 Blinding factor r generated, B = r * U computed (point length: %d)\n", len(crypto.PointCompress(B)))

	// 4. Simulate share collection from servers
	fmt.Printf("📡 Simulating share collection from servers...\n")

	for i, serverURL := range demo.serverURLs {
		if i >= demo.threshold {
			break // Only need threshold shares
		}

		serverAuthCode := serverAuthCodes[serverURL]

		// In a real implementation, this would use the JSON-RPC client
		fmt.Printf("  ✅ Would collect share %d from %s (auth: %s...)\n",
			i+1, serverURL, serverAuthCode[:8])
	}

	// 5. Simulate secret reconstruction
	fmt.Printf("🔧 Simulating secret reconstruction from %d shares...\n", demo.threshold)
	fmt.Printf("🗝️  Simulating encryption key derivation\n")
	fmt.Printf("🔓 Simulating file decryption\n")

	fmt.Printf("✅ Recovery workflow demonstrated successfully!\n")

	return nil
}

func showHelp() {
	fmt.Print(`OpenADP Authentication Code Demo

USAGE:
    openadp-demo [OPTIONS]

OPTIONS:
    -servers <urls>       Comma-separated list of server URLs
    -pin <pin>           User PIN/password for demo (default: demo123)
    -device <id>         Device identifier (default: demo-device)
    -backup <id>         Backup identifier (default: demo-backup.txt)
    -version             Show version information
    -help                Show this help message

EXAMPLES:
    # Run demo with default settings
    openadp-demo

    # Run demo with custom servers
    openadp-demo -servers "https://server1.com,https://server2.com,https://server3.com"

    # Run demo with custom parameters
    openadp-demo -pin "mypin123" -device "laptop-001" -backup "documents.tar.gz"

This demo shows the complete OpenADP authentication code workflow including
cryptographic operations, secret sharing, and recovery protocols.
`)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
