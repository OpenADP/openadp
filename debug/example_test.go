package debug

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/openadp/openadp/sdk/go/client"
	"github.com/openadp/openadp/sdk/go/common"
)

func TestDebugModeExample(t *testing.T) {
	// Enable debug mode
	SetDebugMode(true)
	defer SetDebugMode(false)

	fmt.Println("\n=== Debug Mode Example ===")

	// Test 1: Deterministic secret generation
	fmt.Println("1. Testing deterministic secret generation:")
	secret := GetDeterministicRandomScalar()
	fmt.Printf("   Secret r = %s (should be 1)\n", secret.String())

	// Test 2: Deterministic polynomial coefficients
	fmt.Println("2. Testing deterministic polynomial coefficients:")
	for i := 0; i < 3; i++ {
		coeff := GetDeterministicPolynomialCoefficient()
		fmt.Printf("   Coefficient %d = %s\n", i+1, coeff.String())
	}

	// Reset counter for next test
	SetDebugMode(false)
	SetDebugMode(true)

	// Test 3: Shamir secret sharing with deterministic coefficients
	fmt.Println("3. Testing Shamir secret sharing with debug mode:")
	secret = big.NewInt(42) // Test secret
	threshold := 2
	numShares := 3

	shares, err := client.MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	fmt.Printf("   Original secret: %s\n", secret.String())
	fmt.Printf("   Created %d shares with threshold %d:\n", len(shares), threshold)
	for i, share := range shares {
		fmt.Printf("     Share %d: x=%s, y=%s\n", i+1, share.X.String(), share.Y.String())
	}

	// Recover secret from first 2 shares
	recoveryShares := shares[:threshold]
	recoveredSecret, err := client.RecoverSecret(recoveryShares)
	if err != nil {
		t.Fatalf("Failed to recover secret: %v", err)
	}

	fmt.Printf("   Recovered secret: %s\n", recoveredSecret.String())

	if recoveredSecret.Cmp(secret) != 0 {
		t.Errorf("Recovery failed: expected %s, got %s", secret.String(), recoveredSecret.String())
	} else {
		fmt.Println("   ✅ Secret recovery successful!")
	}

	// Test 4: Point operations
	fmt.Println("4. Testing point operations:")
	uid := []byte("alice@example.com")
	did := []byte("laptop")
	bid := []byte("document.txt")
	pin := []byte("password123")

	H := common.H(uid, did, bid, pin)
	fmt.Printf("   H(uid,did,bid,pin) = (%s, %s)\n", H.X.String()[:20]+"...", H.Y.String()[:20]+"...")

	// Use deterministic r = 1
	r := GetDeterministicRandomScalar()
	rH := common.PointMul(r, H)
	fmt.Printf("   r * H = (%s, %s)\n", rH.X.String()[:20]+"...", rH.Y.String()[:20]+"...")

	// Since r = 1, rH should equal H
	if H.X.Cmp(rH.X) != 0 || H.Y.Cmp(rH.Y) != 0 {
		t.Error("Expected r*H = H when r = 1")
	} else {
		fmt.Println("   ✅ Point multiplication verified (r=1 gives r*H = H)")
	}

	fmt.Println("=== Debug Mode Example Complete ===\n")
}
