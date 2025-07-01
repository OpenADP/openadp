package main

import (
	"fmt"
	"log"

	"github.com/openadp/ocrypt/ocrypt"
)

func main() {
	fmt.Println("🔐 Ocrypt Basic Example")
	fmt.Println("=======================")

	// Example data to encrypt
	secretData := "This is my secret information!"
	password := "mySecurePassword123"
	userID := "alice"
	appID := "myapp"

	fmt.Printf("Original secret: %s\n", secretData)
	fmt.Printf("Password: %s\n", password)
	fmt.Println()

	// Register (encrypt and store) the secret
	fmt.Println("📝 Registering secret...")
	metadata, err := ocrypt.Register(userID, appID, []byte(secretData), password, 10, "")
	if err != nil {
		log.Fatalf("Failed to register secret: %v", err)
	}

	fmt.Printf("✅ Secret registered successfully!\n")
	fmt.Printf("Metadata length: %d bytes\n", len(metadata))
	fmt.Println()

	// Recover (decrypt) the secret
	fmt.Println("🔓 Recovering secret...")
	recoveredSecret, remaining, newMetadata, err := ocrypt.Recover(metadata, password, "")
	if err != nil {
		log.Fatalf("Failed to recover secret: %v", err)
	}

	fmt.Printf("✅ Secret recovered successfully!\n")
	fmt.Printf("Recovered secret: %s\n", recoveredSecret)
	fmt.Printf("Remaining attempts: %d\n", remaining)
	fmt.Printf("New metadata length: %d bytes\n", len(newMetadata))
	fmt.Println()

	// Verify the secret matches
	if string(recoveredSecret) == secretData {
		fmt.Println("🎉 Success! Original and recovered secrets match!")
	} else {
		fmt.Println("❌ Error: Secrets don't match!")
	}

	// Try with wrong password to demonstrate security
	fmt.Println("\n🚫 Testing with wrong password...")
	_, _, _, err = ocrypt.Recover(metadata, "wrongPassword", "")
	if err != nil {
		fmt.Printf("✅ Correctly rejected wrong password: %v\n", err)
	} else {
		fmt.Println("❌ ERROR: Wrong password was accepted!")
	}
}
