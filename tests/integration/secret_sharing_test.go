package integration

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/openadp/openadp/pkg/client"
	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/sharing"
)

func TestSecretSharingBasic(t *testing.T) {
	fmt.Println("Testing basic secret sharing...")

	// Create a test secret
	secret, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	// Create shares
	shares, err := sharing.MakeRandomShares(secret, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	fmt.Printf("Created %d shares with threshold 2\n", len(shares))

	// Recover secret from shares
	recoveredSecret, err := sharing.RecoverSecret(shares[:2])
	if err != nil {
		t.Fatalf("Failed to recover secret: %v", err)
	}

	// Verify the recovered secret matches the original
	if secret.Cmp(recoveredSecret) != 0 {
		t.Errorf("Recovered secret doesn't match original")
		t.Errorf("Original:  %s", secret.String())
		t.Errorf("Recovered: %s", recoveredSecret.String())
	}

	fmt.Println("✅ Basic secret sharing test passed")
}

func TestSecretSharingWithServer(t *testing.T) {
	fmt.Println("Testing secret sharing with server...")

	// Start test servers
	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	testServers, err := serverManager.StartServers(9200, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}

	fallbackServers := serverManager.GetServerURLs()
	fmt.Printf("Started %d test servers: %v\n", len(testServers), fallbackServers)

	c := client.NewClient("", fallbackServers, 5*time.Second, 3)

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available")
	}

	fmt.Printf("Using %d live servers\n", liveCount)

	// Test parameters
	uid := "sharing_test@example.com"
	did := "test_device"
	bid := "test_backup"
	version := 1
	maxGuesses := 10
	expiration := 0

	// Create a test secret and shares
	secret, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	shares, err := sharing.MakeRandomShares(secret, 2, 3) // minimum=2, shares=3
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	fmt.Printf("Secret: %s\n", secret.String())
	fmt.Printf("Created %d shares\n", len(shares))

	// Register shares with server
	for i, share := range shares {
		x := int(share.X.Int64()) // Convert *big.Int to int
		y := share.Y.Bytes()

		success, err := c.RegisterSecret(uid, did, fmt.Sprintf("%s_%d", bid, i), version, x, y, maxGuesses, expiration, nil)
		if !success {
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			t.Errorf("Failed to register share %d: %s", i, errMsg)
		} else {
			fmt.Printf("✅ Registered share %d\n", i)
		}
	}

	fmt.Println("✅ Secret sharing with server test passed")
}

func TestSecretSharingRecovery(t *testing.T) {
	fmt.Println("Testing secret sharing recovery...")

	// Start test servers
	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	testServers, err := serverManager.StartServers(9210, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}

	fallbackServers := serverManager.GetServerURLs()
	fmt.Printf("Started %d test servers: %v\n", len(testServers), fallbackServers)

	c := client.NewClient("", fallbackServers, 5*time.Second, 3)

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available")
	}

	// Test parameters
	uid := "recovery_test@example.com"
	did := "test_device"
	bid := "test_backup"
	version := 1
	maxGuesses := 10
	expiration := 0

	// Create a test secret and shares
	secret, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	shares, err := sharing.MakeRandomShares(secret, 2, 3) // minimum=2, shares=3
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	fmt.Printf("Original secret: %s\n", secret.String())

	// Register shares with server
	for i, share := range shares {
		x := int(share.X.Int64()) // Convert *big.Int to int
		y := share.Y.Bytes()

		success, err := c.RegisterSecret(uid, did, fmt.Sprintf("%s_%d", bid, i), version, x, y, maxGuesses, expiration, nil)
		if !success {
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			t.Errorf("Failed to register share %d: %s", i, errMsg)
		}
	}

	// Simulate recovery by reconstructing from first 2 shares
	recoveredSecret, err := sharing.RecoverSecret(shares[:2])
	if err != nil {
		t.Fatalf("Failed to recover secret: %v", err)
	}

	// Verify the recovered secret matches the original
	if secret.Cmp(recoveredSecret) != 0 {
		t.Errorf("Recovered secret doesn't match original")
		t.Errorf("Original:  %s", secret.String())
		t.Errorf("Recovered: %s", recoveredSecret.String())
	} else {
		fmt.Printf("✅ Recovered secret matches: %s\n", recoveredSecret.String())
	}

	fmt.Println("✅ Secret sharing recovery test passed")
}

func TestSecretSharingThresholds(t *testing.T) {
	fmt.Println("Testing secret sharing thresholds...")

	// Test different threshold configurations
	testCases := []struct {
		numShares int
		threshold int
	}{
		{3, 2},
		{5, 3},
		{7, 4},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d_of_%d", tc.threshold, tc.numShares), func(t *testing.T) {
			// Create a test secret
			secret, err := rand.Int(rand.Reader, crypto.Q)
			if err != nil {
				t.Fatalf("Failed to generate random secret: %v", err)
			}

			// Create shares - correct parameter order: minimum, shares
			shares, err := sharing.MakeRandomShares(secret, tc.threshold, tc.numShares)
			if err != nil {
				t.Fatalf("Failed to create shares: %v", err)
			}

			// Test with exactly threshold shares
			recoveredSecret, err := sharing.RecoverSecret(shares[:tc.threshold])
			if err != nil {
				t.Fatalf("Failed to recover secret with threshold shares: %v", err)
			}

			if secret.Cmp(recoveredSecret) != 0 {
				t.Errorf("Recovered secret doesn't match original for %d-of-%d", tc.threshold, tc.numShares)
			}

			// Test with insufficient shares - Lagrange interpolation will produce a result,
			// but it won't be the correct secret (mathematical property, not an error)
			if tc.threshold > 1 {
				insufficientRecovered, err := sharing.RecoverSecret(shares[:tc.threshold-1])
				if err != nil {
					t.Errorf("Unexpected error with insufficient shares: %v", err)
				}

				// The recovered value should be different from the original secret
				if secret.Cmp(insufficientRecovered) == 0 {
					t.Errorf("Insufficient shares should not recover the correct secret for %d-of-%d", tc.threshold, tc.numShares)
				}
			}

			fmt.Printf("✅ %d-of-%d threshold test passed\n", tc.threshold, tc.numShares)
		})
	}

	fmt.Println("✅ Secret sharing thresholds test passed")
}
