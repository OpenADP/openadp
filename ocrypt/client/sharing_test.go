package client

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/openadp/ocrypt/common"
)

func TestRecoverPointSecret(t *testing.T) {
	// Test point-based secret reconstruction

	// Step 1: Create a random secret
	secret, err := rand.Int(rand.Reader, common.Q)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	// Step 2: Create scalar shares using traditional Shamir secret sharing
	threshold := 2
	numShares := 3
	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	// Step 3: Convert scalar shares to point shares (simulate server behavior)
	// Each server would compute si * B where B is the input point
	B := common.G // Use generator point as B
	pointShares := make([]*PointShare, len(shares))

	for i, share := range shares {
		// Compute si * B (this is what the server returns)
		siB := common.PointMul(share.Y, B)
		siB2D := common.Unexpand(siB)

		pointShares[i] = &PointShare{
			X:     share.X,
			Point: siB2D,
		}
	}

	// Step 4: Recover the secret point using point-based reconstruction
	recoveredSB, err := RecoverPointSecret(pointShares[:threshold])
	if err != nil {
		t.Fatalf("Failed to recover point secret: %v", err)
	}

	// Step 5: Verify that we recovered s*B correctly
	expectedSB := common.PointMul(secret, B)
	expectedSB2D := common.Unexpand(expectedSB)

	if recoveredSB.X.Cmp(expectedSB2D.X) != 0 || recoveredSB.Y.Cmp(expectedSB2D.Y) != 0 {
		t.Errorf("Point reconstruction failed")
		t.Errorf("Expected s*B: (%s, %s)", expectedSB2D.X.String(), expectedSB2D.Y.String())
		t.Errorf("Recovered s*B: (%s, %s)", recoveredSB.X.String(), recoveredSB.Y.String())
	}

	t.Logf("✅ Point-based secret reconstruction test passed")
	t.Logf("Secret: %s", secret.String())
	t.Logf("Expected s*B: (%s, %s)", expectedSB2D.X.String(), expectedSB2D.Y.String())
	t.Logf("Recovered s*B: (%s, %s)", recoveredSB.X.String(), recoveredSB.Y.String())
}

func TestRecoverScalarSecret(t *testing.T) {
	// Test scalar-based secret reconstruction

	// Step 1: Create a random secret
	secret, err := rand.Int(rand.Reader, common.Q)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	// Step 2: Create scalar shares using traditional Shamir secret sharing
	threshold := 2
	numShares := 3
	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	// Step 3: Recover the secret using scalar-based reconstruction
	recoveredSecret, err := RecoverSecret(shares[:threshold])
	if err != nil {
		t.Fatalf("Failed to recover scalar secret: %v", err)
	}

	// Step 4: Verify that we recovered the secret correctly
	if recoveredSecret.Cmp(secret) != 0 {
		t.Errorf("Scalar reconstruction failed")
		t.Errorf("Expected secret: %s", secret.String())
		t.Errorf("Recovered secret: %s", recoveredSecret.String())
	} else {
		t.Logf("✅ Scalar-based secret reconstruction test passed")
		t.Logf("Secret: %s", secret.String())
	}
}

func TestOpenADPWorkflow(t *testing.T) {
	// Test the complete OpenADP encryption/decryption workflow

	// Simulate encryption phase
	uid := "test-user"
	did := "test-device"
	bid := "test-backup"
	pin := []byte{0x12, 0x34}

	// Step 1: Generate secret and create point (encryption)
	secret, err := rand.Int(rand.Reader, common.Q)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	U := common.H([]byte(uid), []byte(did), []byte(bid), pin)
	S := common.PointMul(secret, U) // S = secret * U (encryption key point)

	t.Logf("Secret: %s", secret.String())
	t.Logf("U: (%s, %s)", common.Unexpand(U).X.String(), common.Unexpand(U).Y.String())
	t.Logf("S = secret * U: (%s, %s)", common.Unexpand(S).X.String(), common.Unexpand(S).Y.String())

	// Step 2: Create scalar shares (what gets stored on servers)
	threshold := 2
	numShares := 3
	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("Failed to create shares: %v", err)
	}

	t.Logf("Shares: %v", shares)

	// Step 3: Derive encryption key from S
	encKeyOriginal := common.DeriveEncKey(S)

	// Simulate recovery phase
	// Step 4: Generate random r and compute B (recovery)
	r, err := rand.Int(rand.Reader, common.Q)
	if err != nil {
		t.Fatalf("Failed to generate random r: %v", err)
	}

	rInv := new(big.Int).ModInverse(r, common.Q)
	if rInv == nil {
		t.Fatalf("Failed to compute modular inverse")
	}

	// Verify r * r_inv = 1 mod q
	check := new(big.Int).Mul(r, rInv)
	check.Mod(check, common.Q)
	if check.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("r * r_inv != 1 mod q: got %s", check.String())
	}

	B := common.PointMul(r, U) // B = r * U

	t.Logf("r: %s", r.String())
	t.Logf("r_inv: %s", rInv.String())
	t.Logf("B = r * U: (%s, %s)", common.Unexpand(B).X.String(), common.Unexpand(B).Y.String())

	// Step 5: Simulate server responses (si * B for each share)
	pointShares := make([]*PointShare, len(shares))
	for i, share := range shares {
		siB := common.PointMul(share.Y, B) // si * B
		siB2D := common.Unexpand(siB)

		pointShares[i] = &PointShare{
			X:     share.X,
			Point: siB2D,
		}

		t.Logf("Share %d: si=%s, si*B=(%s, %s)", i, share.Y.String(), siB2D.X.String(), siB2D.Y.String())
	}

	// Step 6: Recover s*B using point-based reconstruction
	recoveredSB, err := RecoverPointSecret(pointShares[:threshold])
	if err != nil {
		t.Fatalf("Failed to recover point secret: %v", err)
	}

	t.Logf("Recovered s*B: (%s, %s)", recoveredSB.X.String(), recoveredSB.Y.String())

	// Verify s*B is correct by computing it directly
	expectedSB := common.PointMul(secret, B)
	expectedSB2D := common.Unexpand(expectedSB)
	t.Logf("Expected s*B: (%s, %s)", expectedSB2D.X.String(), expectedSB2D.Y.String())

	if recoveredSB.X.Cmp(expectedSB2D.X) != 0 || recoveredSB.Y.Cmp(expectedSB2D.Y) != 0 {
		t.Errorf("Recovered s*B doesn't match expected s*B")
		return
	}

	// Step 7: Compute s*U = r_inv * (s*B)
	recoveredSB4D := common.Expand(recoveredSB)
	recoveredSU := common.PointMul(rInv, recoveredSB4D)

	t.Logf("Recovered s*U: (%s, %s)", common.Unexpand(recoveredSU).X.String(), common.Unexpand(recoveredSU).Y.String())

	// Step 8: Derive encryption key from recovered point
	encKeyRecovered := common.DeriveEncKey(recoveredSU)

	// Step 9: Verify keys match
	if len(encKeyOriginal) != len(encKeyRecovered) {
		t.Errorf("Key lengths don't match: original=%d, recovered=%d", len(encKeyOriginal), len(encKeyRecovered))
	}

	for i := 0; i < len(encKeyOriginal) && i < len(encKeyRecovered); i++ {
		if encKeyOriginal[i] != encKeyRecovered[i] {
			t.Errorf("Keys don't match at byte %d: original=0x%02x, recovered=0x%02x", i, encKeyOriginal[i], encKeyRecovered[i])
			break
		}
	}

	// Verify the points are the same
	S2D := common.Unexpand(S)
	recoveredSU2D := common.Unexpand(recoveredSU)

	if S2D.X.Cmp(recoveredSU2D.X) != 0 || S2D.Y.Cmp(recoveredSU2D.Y) != 0 {
		t.Errorf("Secret points don't match")
		t.Errorf("Original S: (%s, %s)", S2D.X.String(), S2D.Y.String())
		t.Errorf("Recovered S: (%s, %s)", recoveredSU2D.X.String(), recoveredSU2D.Y.String())
	} else {
		t.Logf("✅ OpenADP workflow test passed - keys match!")
		t.Logf("Original key: %x", encKeyOriginal[:16])
		t.Logf("Recovered key: %x", encKeyRecovered[:16])
	}
}
