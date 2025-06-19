package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/sharing"
)

func main() {
	fmt.Println("Debug the integer to bytes conversion issue.")
	fmt.Println()

	// Test with actual secret sharing
	s, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random secret: %v", err))
	}

	shares, err := sharing.MakeRandomShares(s, 2, 2)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate shares: %v", err))
	}

	fmt.Printf("crypto.Q = %s\n", crypto.Q.String())
	fmt.Printf("crypto.Q bits: %d\n", crypto.Q.BitLen())

	max256 := new(big.Int)
	max256.Exp(big.NewInt(2), big.NewInt(256), nil)
	max256.Sub(max256, big.NewInt(1))
	fmt.Printf("Max value for 32 bytes: %s\n", max256.String())
	fmt.Printf("crypto.Q < 2^256: %t\n", crypto.Q.Cmp(max256) < 0)
	fmt.Println()

	for i, share := range shares {
		x, y := share.X, share.Y
		fmt.Printf("Share %d: x=%s, y=%s\n", i+1, x.String(), y.String())
		fmt.Printf("  Y bits: %d\n", y.BitLen())
		fmt.Printf("  Y < 2^256: %t\n", y.Cmp(max256) < 0)
		fmt.Printf("  Y < crypto.Q: %t\n", y.Cmp(crypto.Q) < 0)

		// Test conversion
		// Calculate minimum bytes needed
		bytesNeeded := (y.BitLen() + 7) / 8
		fmt.Printf("  Minimum bytes needed: %d\n", bytesNeeded)

		// Try to convert to exactly 32 bytes
		yBytes := y.Bytes()
		if len(yBytes) > 32 {
			fmt.Printf("  ❌ Y too large for 32 bytes: %d bytes\n", len(yBytes))
		} else {
			// Pad to 32 bytes if needed
			if len(yBytes) < 32 {
				padded := make([]byte, 32)
				copy(padded[32-len(yBytes):], yBytes)
				yBytes = padded
			}
			fmt.Printf("  ✅ Conversion to 32 bytes successful: %d bytes\n", len(yBytes))

			// Test if we can convert back
			yRecovered := new(big.Int).SetBytes(yBytes)
			fmt.Printf("  ✅ Round-trip successful: %t\n", y.Cmp(yRecovered) == 0)

			// Test with different byte sizes
			for _, byteSize := range []int{31, 32, 33} {
				if len(y.Bytes()) <= byteSize {
					fmt.Printf("  ✅ Conversion to %d bytes: OK\n", byteSize)
				} else {
					fmt.Printf("  ❌ Conversion to %d bytes: value too large\n", byteSize)
				}
			}
		}
		fmt.Println()
	}

	// Test the specific validation logic
	fmt.Println("Testing server validation logic:")
	for i, share := range shares {
		y := share.Y
		yStr := y.String()
		fmt.Printf("Share %d as string: length=%d\n", i+1, len(yStr))

		// Simulate the JSON-RPC server conversion
		yInt := new(big.Int)
		yInt.SetString(yStr, 10)
		yBytes := yInt.Bytes()

		// Handle zero case
		if len(yBytes) == 0 {
			yBytes = []byte{0}
		}

		validationResult := len(yBytes) <= 32
		fmt.Printf("  JSON-RPC conversion successful: %d bytes, validation: %t\n", len(yBytes), validationResult)
	}
}
