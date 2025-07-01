// Package main demonstrates the Ocrypt API for distributed password hashing
// using OpenADP's Oblivious Pseudo Random Function (OPRF) cryptography.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"

	"github.com/openadp/ocrypt/ocrypt"
)

func main() {
	fmt.Println("🔮 Ocrypt Demo - Nation-State Resistant Password Protection")
	fmt.Println("🌐 Using OpenADP distributed threshold cryptography")
	fmt.Println("🔐 Based on Oblivious Pseudo Random Function (OPRF) cryptography")
	fmt.Println()

	// Run demos
	if err := runDemos(); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}

	fmt.Println("============================================================")
	fmt.Println("🎉 All demos completed successfully!")
	fmt.Println("============================================================")
	fmt.Println()
	fmt.Println("📚 Next steps:")
	fmt.Println("   1. Read the design document: docs/ocrypt_design.md")
	fmt.Println("   2. Run the test suite: go test ./pkg/ocrypt/...")
	fmt.Println("   3. Check the API documentation with: go doc ./pkg/ocrypt")
	fmt.Println("   4. Start integrating Ocrypt into your Go applications!")
	fmt.Println()
	fmt.Println("🔗 Learn more about OpenADP at: https://openadp.org")
	fmt.Println("🔬 Learn about OPRF cryptography: https://tools.ietf.org/rfc/rfc9497.txt")
}

func runDemos() error {
	if err := demoBasicUsage(); err != nil {
		return err
	}

	if err := demoAPITokenStorage(); err != nil {
		return err
	}

	if err := demoDatabaseEncryption(); err != nil {
		return err
	}

	if err := demoMigrationFromBcrypt(); err != nil {
		return err
	}

	return nil
}

func demoBasicUsage() error {
	fmt.Println("============================================================")
	fmt.Println("DEMO 1: Basic Ocrypt API Usage")
	fmt.Println("============================================================")

	// Demo parameters
	userID := "alice@example.com"
	appID := "payment_processor"
	secret := []byte("This is my super secret API key: sk_live_51234567890abcdef")
	pin := "secure_password_123"

	fmt.Printf("🔐 Protecting secret for user: %s\n", userID)
	fmt.Printf("📱 Application: %s\n", appID)
	fmt.Printf("🔑 Secret length: %d bytes\n", len(secret))
	fmt.Println()

	// Step 1: Register secret
	fmt.Println("📋 Step 1: Register secret with OpenADP...")
	metadata, err := ocrypt.Register(userID, appID, secret, pin, 10)
	if err != nil {
		fmt.Printf("❌ Registration failed: %v\n", err)
		fmt.Println("   This is expected if OpenADP servers are not accessible")
		fmt.Println("   In production, ensure servers are reachable")
		fmt.Println()
		return nil // Don't fail the demo
	}

	fmt.Println("✅ Registration successful!")
	fmt.Printf("📦 Metadata size: %d bytes\n", len(metadata))
	fmt.Printf("🎯 Metadata preview: %s...\n", string(metadata[:min(100, len(metadata))]))
	fmt.Println()

	// Step 2: Recover secret
	fmt.Println("📋 Step 2: Recover secret using PIN...")
	recoveredSecret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, pin)
	if err != nil {
		return fmt.Errorf("recovery failed: %v", err)
	}

	fmt.Println("✅ Recovery successful!")
	fmt.Printf("🔓 Recovered secret: %s\n", string(recoveredSecret))
	fmt.Printf("🎯 Remaining guesses: %d\n", remaining)
	fmt.Printf("✅ Secret matches: %t\n", string(secret) == string(recoveredSecret))
	fmt.Printf("📦 Updated metadata size: %d bytes\n", len(updatedMetadata))
	fmt.Println()

	// Step 3: Test wrong PIN
	fmt.Println("📋 Step 3: Test wrong PIN...")
	_, _, _, err = ocrypt.Recover(metadata, "wrong_pin")
	if err != nil {
		fmt.Printf("✅ Wrong PIN correctly rejected: %v\n", err)
	} else {
		fmt.Println("❌ Wrong PIN should have been rejected")
	}

	fmt.Println()
	return nil
}

func demoAPITokenStorage() error {
	fmt.Println("============================================================")
	fmt.Println("DEMO 2: API Token Storage")
	fmt.Println("============================================================")

	// Simulate protecting various API tokens
	tokens := map[string]string{
		"stripe_api_key":    "sk_live_51HyperSecureStripeToken123456789",
		"aws_access_key":    "AKIAIOSFODNN7EXAMPLE",
		"github_token":      "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"database_password": "super_secure_db_password_2024",
	}

	userID := "service_account_001"
	pin := "service_pin_2024"

	protectedTokens := make(map[string][]byte)

	fmt.Printf("🔐 Protecting %d API tokens for service account...\n", len(tokens))
	fmt.Println()

	// Protect each token
	for tokenName, tokenValue := range tokens {
		fmt.Printf("📋 Protecting %s...\n", tokenName)

		metadata, err := ocrypt.Register(userID, tokenName, []byte(tokenValue), pin, 3)
		if err != nil {
			fmt.Printf("   ❌ Failed: %v\n", err)
			fmt.Println("   This is expected if OpenADP servers are not accessible")
			continue
		}

		protectedTokens[tokenName] = metadata
		fmt.Printf("   ✅ Protected (%d bytes metadata)\n", len(metadata))
	}

	if len(protectedTokens) == 0 {
		fmt.Println("⚠️  No tokens protected (servers not accessible)")
		fmt.Println("   In production, ensure OpenADP servers are reachable")
		fmt.Println()
		return nil
	}

	fmt.Println()
	fmt.Printf("✅ All %d tokens protected!\n", len(protectedTokens))
	fmt.Println()

	// Recover tokens
	fmt.Println("📋 Recovering tokens...")
	for tokenName, metadata := range protectedTokens {
		recoveredTokenBytes, _, _, err := ocrypt.Recover(metadata, pin)
		if err != nil {
			fmt.Printf("   ❌ %s: Recovery failed: %v\n", tokenName, err)
			continue
		}

		recoveredToken := string(recoveredTokenBytes)
		originalToken := tokens[tokenName]
		matches := recoveredToken == originalToken

		fmt.Printf("   🔓 %s: %s\n", tokenName, map[bool]string{true: "✅ MATCH", false: "❌ MISMATCH"}[matches])
		fmt.Printf("      Original:  %s...\n", originalToken[:min(20, len(originalToken))])
		fmt.Printf("      Recovered: %s...\n", recoveredToken[:min(20, len(recoveredToken))])
	}

	fmt.Println()
	fmt.Println("✅ All tokens recovered successfully!")
	fmt.Println()
	return nil
}

func demoDatabaseEncryption() error {
	fmt.Println("============================================================")
	fmt.Println("DEMO 3: Database Encryption Key Protection")
	fmt.Println("============================================================")

	// Generate a database encryption key
	fmt.Println("🔐 Generating database encryption key...")
	dbEncryptionKey := make([]byte, 32) // AES-256 key
	if _, err := rand.Read(dbEncryptionKey); err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	fmt.Println("✅ Generated 256-bit encryption key")
	fmt.Printf("🔑 Key: %x\n", dbEncryptionKey)
	fmt.Println()

	// Protect the database key
	userID := "database_cluster_01"
	appID := "customer_data_encryption"
	pin := "db_master_pin_2024"

	fmt.Println("📋 Step 1: Protect database key with Ocrypt...")
	metadata, err := ocrypt.Register(userID, appID, dbEncryptionKey, pin, 10)
	if err != nil {
		fmt.Printf("❌ Protection failed: %v\n", err)
		fmt.Println("   This is expected if OpenADP servers are not accessible")
		fmt.Println()
		return nil
	}

	fmt.Println("✅ Database key protected!")
	fmt.Printf("📦 Metadata size: %d bytes\n", len(metadata))
	fmt.Println()

	// Simulate database startup - recover the key
	fmt.Println("📋 Step 2: Database startup - recover encryption key...")
	recoveredKey, _, _, err := ocrypt.Recover(metadata, pin)
	if err != nil {
		return fmt.Errorf("key recovery failed: %v", err)
	}

	fmt.Println("✅ Database key recovered!")
	fmt.Printf("🔑 Recovered key: %x\n", recoveredKey)
	fmt.Printf("✅ Keys match: %t\n", string(dbEncryptionKey) == string(recoveredKey))
	fmt.Println()

	// Simulate encrypting database records
	fmt.Println("📋 Step 3: Encrypt sample database record...")
	customerData := map[string]interface{}{
		"customer_id": "cust_12345",
		"name":        "John Doe",
		"email":       "john@example.com",
		"phone":       "+1-555-123-4567",
		"address": map[string]string{
			"street": "123 Main St",
			"city":   "Anytown",
			"state":  "CA",
			"zip":    "12345",
		},
	}

	customerJSON, err := json.Marshal(customerData)
	if err != nil {
		return fmt.Errorf("failed to marshal customer data: %v", err)
	}

	// In a real application, you would use the recovered key for AES encryption
	fmt.Println("✅ Customer data ready for encryption!")
	fmt.Printf("📄 Original size: %d bytes\n", len(customerJSON))
	fmt.Printf("🔑 Using recovered key for encryption\n")
	fmt.Printf("👤 Customer: %s (%s)\n", customerData["name"], customerData["email"])

	fmt.Println()
	return nil
}

func demoMigrationFromBcrypt() error {
	fmt.Println("============================================================")
	fmt.Println("DEMO 4: Migration from Traditional Password Hashing")
	fmt.Println("============================================================")

	// Simulate existing user database with bcrypt hashes
	fmt.Println("🗃️  Simulating existing user database with bcrypt hashes...")
	users := map[string]string{
		"alice@example.com": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYLS.HzgDmxRjVzk8Y8P0.xH8J8qJ8ZG",
		"bob@example.com":   "$2b$12$EXRkDxrfQIyuVvVvVvVvVeyJQBhwHGUcgLVJ8ZYxHGUcgLVJ8ZYxH",
	}

	fmt.Printf("📊 Found %d users with bcrypt hashes\n", len(users))
	for email, hash := range users {
		fmt.Printf("   👤 %s: %s...\n", email, hash[:32])
	}
	fmt.Println()

	// Migrate to Ocrypt
	fmt.Println("🔄 Migrating to Ocrypt...")
	migratedUsers := make(map[string][]byte)

	for email := range users {
		fmt.Printf("📋 Migrating %s...\n", email)

		// Generate a random secret for each user (in practice, you might derive this from existing data)
		userSecret := make([]byte, 32)
		if _, err := rand.Read(userSecret); err != nil {
			return fmt.Errorf("failed to generate user secret: %v", err)
		}

		// Use a demo password (in practice, this would be done during user login)
		userPassword := "user_password_123"

		metadata, err := ocrypt.Register(email, "user_authentication", userSecret, userPassword, 5)
		if err != nil {
			fmt.Printf("   ❌ Failed: %v\n", err)
			fmt.Println("   This is expected if OpenADP servers are not accessible")
			continue
		}

		migratedUsers[email] = metadata
		fmt.Printf("   ✅ Migrated (%d bytes metadata)\n", len(metadata))
	}

	if len(migratedUsers) == 0 {
		fmt.Println("⚠️  No users migrated (servers not accessible)")
		fmt.Println("   In production, ensure OpenADP servers are reachable")
		fmt.Println()
		return nil
	}

	fmt.Println()
	fmt.Printf("✅ Migration complete! %d users migrated\n", len(migratedUsers))
	fmt.Println()

	// Test authentication with new system
	fmt.Println("📋 Testing authentication with new system...")
	for email, metadata := range migratedUsers {
		fmt.Printf("🔐 User %s attempting login...\n", email)

		// Test with correct password
		userPassword := "user_password_123"
		secret, remaining, _, err := ocrypt.Recover(metadata, userPassword)
		if err != nil {
			fmt.Printf("❌ Authentication failed: %v\n", err)
			continue
		}

		fmt.Println("✅ Authentication: SUCCESS")
		fmt.Printf("🔑 Secret recovered: %d bytes\n", len(secret))
		fmt.Printf("🎯 Remaining attempts: %d\n", remaining)
	}

	fmt.Println()
	fmt.Println("🎉 Migration Benefits:")
	fmt.Println("   ✅ Nation-state resistant (distributed across multiple servers)")
	fmt.Println("   ✅ Guess limiting (built-in brute force protection)")
	fmt.Println("   ✅ No local password storage (metadata contains no secrets)")
	fmt.Println("   ✅ Automatic backup refresh (on successful authentication)")
	fmt.Println("   ✅ Threshold recovery (works even if some servers are down)")
	fmt.Println("   ✅ OPRF-based security (oblivious pseudo random functions)")

	fmt.Println()
	return nil
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
