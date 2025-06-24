package integration

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openadp/ocrypt/client"
	"github.com/openadp/ocrypt/common"
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
	{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1)), "252-bit max (close to common.q)"},
}

func TestLargeYValues(t *testing.T) {
	fmt.Println("Testing large Y values...")

	// Start test servers using the existing helper
	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	servers, err := serverManager.StartServers(9200, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}
	defer serverManager.StopAllServers()

	// Test cases with different Y values
	testCases := []struct {
		value       *big.Int
		description string
	}{
		{big.NewInt(1), "small value"},
		{big.NewInt(1000000), "medium value"},
		{new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil), "2^64"},
		{new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil), "2^128"},
		{new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), "2^256"},
	}

	// Initialize client with our test servers using ServerInfo with public keys
	serverInfos, err := serverManager.GetServerInfos()
	if err != nil {
		t.Fatalf("Failed to get server info from test servers: %v", err)
	}
	c := client.NewClientWithServerInfo(serverInfos, 5*time.Second, 3)

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Fatalf("No live servers available after starting test servers")
	}

	t.Logf("Started %d test servers, %d are live", len(servers), liveCount)

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
	expiration := 0

	fmt.Printf("Y integer: %s\n", yInt.String())
	fmt.Printf("Y string length: %d\n", len(yInt.String()))
	fmt.Printf("Y bits: %d\n", yInt.BitLen())
	fmt.Printf("Y bytes needed: %d\n", (yInt.BitLen()+7)/8)

	// Check if Y is within valid range (should be < common.Q)
	if yInt.Cmp(common.Q) >= 0 {
		fmt.Printf("⚠️  Y value exceeds common.Q, adjusting...\n")
		yInt = new(big.Int).Mod(yInt, common.Q)
		fmt.Printf("Adjusted Y: %s\n", yInt.String())
	}

	// Convert to bytes for the new client API
	yBytes := yInt.Bytes()
	if len(yBytes) == 0 {
		yBytes = []byte{0} // Handle zero case
	}

	// Try to register
	success, err := c.RegisterSecret(uid, did, bid, version, x, yBytes, maxGuesses, expiration, nil)

	if success {
		fmt.Printf("✅ Registration successful for %s!\n", description)
	} else {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		t.Errorf("Registration failed for %s: %s", description, errMsg)
	}
}

func TestBasicRegistration(t *testing.T) {
	fmt.Println("Testing basic secret registration...")

	// Start test servers using the existing helper
	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	servers, err := serverManager.StartServers(9200, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}
	defer serverManager.StopAllServers()

	// Test parameters
	uid := "test@example.com"
	did := "test_device"
	bid := "test_backup"
	version := 1
	x := 42
	maxGuesses := 10
	expiration := 0

	// Create a test integer for y (within valid range)
	yInt := new(big.Int).SetUint64(123456789012345)
	yBytes := yInt.Bytes()

	fmt.Printf("x as integer: %d\n", x)
	fmt.Printf("y as integer: %s\n", yInt.String())
	fmt.Printf("y as bytes length: %d\n", len(yBytes))

	// Initialize client with our test servers using ServerInfo with public keys
	serverInfos, err := serverManager.GetServerInfos()
	if err != nil {
		t.Fatalf("Failed to get server info from test servers: %v", err)
	}
	c := client.NewClientWithServerInfo(serverInfos, 5*time.Second, 3)

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Fatalf("No live servers available after starting test servers")
	}

	t.Logf("Started %d test servers, %d are live", len(servers), liveCount)
	fmt.Printf("Using %d live servers\n", liveCount)

	// Try to register
	success, err := c.RegisterSecret(uid, did, bid, version, x, yBytes, maxGuesses, expiration, nil)

	if success {
		fmt.Println("✅ Registration successful!")
	} else {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		t.Errorf("Registration failed: %s", errMsg)
	}
}

func TestEdgeCaseValues(t *testing.T) {
	fmt.Println("Testing edge case values...")

	// Start test servers using the existing helper
	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	servers, err := serverManager.StartServers(9200, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}
	defer serverManager.StopAllServers()

	// Initialize client with our test servers using ServerInfo with public keys
	serverInfos, err := serverManager.GetServerInfos()
	if err != nil {
		t.Fatalf("Failed to get server info from test servers: %v", err)
	}
	c := client.NewClientWithServerInfo(serverInfos, 5*time.Second, 3)

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Fatalf("No live servers available after starting test servers")
	}

	t.Logf("Started %d test servers, %d are live", len(servers), liveCount)

	// Test cases for edge values
	edgeCases := []struct {
		yValue      *big.Int
		description string
		shouldPass  bool
	}{
		{big.NewInt(0), "zero value", true},
		{big.NewInt(1), "minimum positive", true},
		{new(big.Int).Sub(common.P, big.NewInt(1)), "maximum valid (P-1)", true},
		{common.P, "exactly P (should fail)", false},
		{new(big.Int).Add(common.P, big.NewInt(1)), "P+1 (should fail)", false},
	}

	for i, tc := range edgeCases {
		t.Run(tc.description, func(t *testing.T) {
			uid := "test@example.com"
			did := "test_device"
			bid := fmt.Sprintf("test_edge_%d", i)
			version := 1
			x := i + 1
			maxGuesses := 10
			expiration := 0

			fmt.Printf("\n--- Testing %s ---\n", tc.description)
			fmt.Printf("Y value: %s\n", tc.yValue.String())

			yBytes := tc.yValue.Bytes()
			if len(yBytes) == 0 {
				yBytes = []byte{0}
			}

			success, err := c.RegisterSecret(uid, did, bid, version, x, yBytes, maxGuesses, expiration, nil)

			if tc.shouldPass {
				if success {
					fmt.Printf("✅ %s passed as expected\n", tc.description)
				} else {
					errMsg := ""
					if err != nil {
						errMsg = err.Error()
					}
					t.Errorf("%s should have passed but failed: %s", tc.description, errMsg)
				}
			} else {
				if !success {
					errMsg := ""
					if err != nil {
						errMsg = err.Error()
					}
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

	// Start test servers using the existing helper
	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	servers, err := serverManager.StartServers(9200, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}
	defer serverManager.StopAllServers()

	// Initialize client with our test servers using ServerInfo with public keys
	serverInfos, err := serverManager.GetServerInfos()
	if err != nil {
		t.Fatalf("Failed to get server info from test servers: %v", err)
	}
	c := client.NewClientWithServerInfo(serverInfos, 5*time.Second, 3)

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Fatalf("No live servers available after starting test servers")
	}

	t.Logf("Started %d test servers, %d are live", len(servers), liveCount)

	// Test parameters
	uid := "concurrent_test@example.com"
	did := "test_device"
	version := 1
	maxGuesses := 10
	expiration := 0

	// Run concurrent registrations
	numConcurrent := 5
	results := make(chan bool, numConcurrent)
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(index int) {
			bid := fmt.Sprintf("concurrent_backup_%d", index)
			x := index + 1
			yInt := big.NewInt(int64(1000000 + index))
			yBytes := yInt.Bytes()

			success, err := c.RegisterSecret(uid, did, bid, version, x, yBytes, maxGuesses, expiration, nil)
			results <- success
			errors <- err
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numConcurrent; i++ {
		success := <-results
		err := <-errors
		if success {
			successCount++
		} else if err != nil {
			fmt.Printf("Registration %d failed: %v\n", i, err)
		}
	}

	fmt.Printf("Concurrent registrations: %d/%d successful\n", successCount, numConcurrent)

	if successCount == 0 {
		t.Error("No concurrent registrations succeeded")
	}
}

// Helper function to sanitize description for use in BID
func sanitizeForBID(description string) string {
	// Replace spaces and special characters with underscores
	result := strings.ReplaceAll(description, " ", "_")
	result = strings.ReplaceAll(result, "^", "_")
	result = strings.ReplaceAll(result, "/", "_")
	return result
}
