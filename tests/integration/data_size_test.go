package integration

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/openadp/openadp/pkg/client"
	"github.com/openadp/openadp/pkg/crypto"
)

// Test cases for different Y value sizes
var testCases = []struct {
	value       *big.Int
	description string
}{
	{big.NewInt(123456789), "small integer"},
	{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(1)), "32-bit max"},
	{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)), "64-bit max"},
	{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)), "128-bit max"},
	{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 200), big.NewInt(1)), "200-bit max"},
	{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1)), "252-bit max (close to crypto.q)"},
}

func TestLargeYValues(t *testing.T) {
	// Initialize client with local test servers
	fallbackServers := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	c, err := client.NewClient("", fallbackServers)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available - make sure local test servers are running")
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			testYSize(t, c, tc.value, tc.description)
		})
	}
}

func testYSize(t *testing.T, c *client.Client, yInt *big.Int, description string) {
	fmt.Printf("\n--- Testing %s ---\n", description)

	// Test parameters
	uid := "test@example.com"
	did := "test_device"
	bid := fmt.Sprintf("test_backup_%s", sanitizeForBID(description))
	version := 1
	x := 42
	maxGuesses := 10
	expiration := int64(0)

	yStr := yInt.String()
	fmt.Printf("Y integer: %s\n", yInt.String())
	fmt.Printf("Y string length: %d\n", len(yStr))
	fmt.Printf("Y bits: %d\n", yInt.BitLen())
	fmt.Printf("Y bytes needed: %d\n", (yInt.BitLen()+7)/8)

	// Check if Y is within valid range (should be < crypto.Q)
	if yInt.Cmp(crypto.Q) >= 0 {
		fmt.Printf("⚠️  Y value exceeds crypto.Q, adjusting...\n")
		yInt = new(big.Int).Mod(yInt, crypto.Q)
		yStr = yInt.String()
		fmt.Printf("Adjusted Y: %s\n", yInt.String())
	}

	// Try to register
	success, errMsg := c.RegisterSecret(uid, did, bid, version, x, yStr, maxGuesses, expiration)

	if success {
		fmt.Printf("✅ Registration successful for %s!\n", description)
	} else {
		t.Errorf("Registration failed for %s: %s", description, errMsg)
	}
}

func TestBasicRegistration(t *testing.T) {
	fmt.Println("Testing basic secret registration...")

	// Test parameters
	uid := "test@example.com"
	did := "test_device"
	bid := "test_backup"
	version := 1
	x := 42
	maxGuesses := 10
	expiration := int64(0)

	// Create a test integer for y (within valid range)
	yInt := big.NewInt(123456789012345678901234567890)
	yStr := yInt.String()

	fmt.Printf("x as integer: %d\n", x)
	fmt.Printf("y as integer: %s\n", yInt.String())
	fmt.Printf("y as string length: %d\n", len(yStr))
	if len(yStr) > 50 {
		fmt.Printf("y string: %s...\n", yStr[:50])
	} else {
		fmt.Printf("y string: %s\n", yStr)
	}

	// Initialize client
	fallbackServers := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	c, err := client.NewClient("", fallbackServers)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available")
	}

	fmt.Printf("Using %d live servers\n", liveCount)

	// Try to register
	success, errMsg := c.RegisterSecret(uid, did, bid, version, x, yStr, maxGuesses, expiration)

	if success {
		fmt.Println("✅ Registration successful!")
	} else {
		t.Errorf("Registration failed: %s", errMsg)
	}
}

func TestEdgeCaseValues(t *testing.T) {
	fmt.Println("Testing edge case values...")

	// Initialize client
	fallbackServers := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	c, err := client.NewClient("", fallbackServers)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available")
	}

	// Test cases for edge values
	edgeCases := []struct {
		yValue      string
		description string
		shouldPass  bool
	}{
		{"0", "zero value", true},
		{"1", "minimum positive", true},
		{new(big.Int).Sub(crypto.Q, big.NewInt(1)).String(), "maximum valid (Q-1)", true},
		{crypto.Q.String(), "exactly Q (should fail)", false},
		{new(big.Int).Add(crypto.Q, big.NewInt(1)).String(), "Q+1 (should fail)", false},
	}

	for i, tc := range edgeCases {
		t.Run(tc.description, func(t *testing.T) {
			uid := "test@example.com"
			did := "test_device"
			bid := fmt.Sprintf("test_edge_%d", i)
			version := 1
			x := i + 1
			maxGuesses := 10
			expiration := int64(0)

			fmt.Printf("\n--- Testing %s ---\n", tc.description)
			fmt.Printf("Y value: %s\n", tc.yValue)

			success, errMsg := c.RegisterSecret(uid, did, bid, version, x, tc.yValue, maxGuesses, expiration)

			if tc.shouldPass {
				if success {
					fmt.Printf("✅ %s passed as expected\n", tc.description)
				} else {
					t.Errorf("%s should have passed but failed: %s", tc.description, errMsg)
				}
			} else {
				if !success {
					fmt.Printf("✅ %s failed as expected: %s\n", tc.description, errMsg)
				} else {
					t.Errorf("%s should have failed but passed", tc.description)
				}
			}
		})
	}
}

func TestConcurrentRegistrations(t *testing.T) {
	fmt.Println("Testing concurrent registrations...")

	// Initialize client
	fallbackServers := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	c, err := client.NewClient("", fallbackServers)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available")
	}

	// Test parameters
	uid := "concurrent_test@example.com"
	did := "test_device"
	version := 1
	maxGuesses := 10
	expiration := int64(0)

	// Number of concurrent registrations to test
	numRegistrations := 5

	// Channel to collect results
	results := make(chan bool, numRegistrations)
	errors := make(chan string, numRegistrations)

	// Launch concurrent registrations
	for i := 0; i < numRegistrations; i++ {
		go func(index int) {
			bid := fmt.Sprintf("concurrent_backup_%d", index)
			x := index + 1
			yInt := big.NewInt(int64(123456789 + index))
			yStr := yInt.String()

			success, errMsg := c.RegisterSecret(uid, did, bid, version, x, yStr, maxGuesses, expiration)
			results <- success
			if !success {
				errors <- errMsg
			} else {
				errors <- ""
			}
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numRegistrations; i++ {
		success := <-results
		errMsg := <-errors
		if success {
			successCount++
		} else {
			fmt.Printf("Registration %d failed: %s\n", i, errMsg)
		}
	}

	fmt.Printf("Concurrent registrations: %d/%d successful\n", successCount, numRegistrations)

	if successCount != numRegistrations {
		t.Errorf("Expected all %d registrations to succeed, got %d", numRegistrations, successCount)
	}
}

// Helper function to sanitize description for use in BID
func sanitizeForBID(description string) string {
	result := ""
	for _, r := range description {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			result += string(r)
		} else if r == ' ' || r == '-' {
			result += "_"
		}
	}
	return result
}

