// Package sharing implements Shamir's secret sharing scheme.
//
// This module provides functions for:
// - Creating random shares from a secret
// - Recovering secrets from a threshold number of shares
// - Working with elliptic curve points for OpenADP
//
// Based on: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
package client

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/openadp/ocrypt/common"
)

// Share represents a (x, y) coordinate pair
type Share struct {
	X, Y *big.Int
}

// PointShare represents a (x, point) pair
type PointShare struct {
	X     *big.Int
	Point *common.Point2D
}

// evalAt evaluates polynomial (coefficient slice) at x
//
// Used to generate Shamir shares in MakeRandomShares below.
func evalAt(poly []*big.Int, x *big.Int, prime *big.Int) *big.Int {
	xPow := big.NewInt(1)
	result := big.NewInt(0)

	for _, coeff := range poly {
		// result = (result + coeff * x_pow) % prime
		term := new(big.Int).Mul(coeff, xPow)
		result.Add(result, term)
		result.Mod(result, prime)

		// x_pow = x_pow * x % prime
		xPow.Mul(xPow, x)
		xPow.Mod(xPow, prime)
	}

	return result
}

// MakeRandomShares generates random Shamir shares for a given secret
func MakeRandomShares(secret *big.Int, minimum, shares int) ([]*Share, error) {
	if minimum > shares {
		return nil, errors.New("pool secret would be irrecoverable")
	}

	prime := common.Q

	// Handle edge case where minimum = 0
	if minimum == 0 {
		// With threshold 0, any single share contains the secret
		// Create constant polynomial f(x) = secret
		points := make([]*Share, shares)
		for i := 0; i < shares; i++ {
			x := big.NewInt(int64(i + 1))
			y := new(big.Int).Set(secret) // All shares have the same y value (the secret)
			points[i] = &Share{
				X: new(big.Int).Set(x),
				Y: new(big.Int).Set(y),
			}
		}
		return points, nil
	}

	// Create random polynomial with secret as constant term
	poly := make([]*big.Int, minimum)
	poly[0] = new(big.Int).Set(secret)

	for i := 1; i < minimum; i++ {
		// Generate random coefficient
		coeff, err := rand.Int(rand.Reader, prime)
		if err != nil {
			return nil, err
		}
		poly[i] = coeff
	}

	// Generate share points by evaluating polynomial at x = 1, 2, ..., shares
	points := make([]*Share, shares)
	for i := 0; i < shares; i++ {
		x := big.NewInt(int64(i + 1))
		y := evalAt(poly, x, prime)
		points[i] = &Share{
			X: new(big.Int).Set(x),
			Y: new(big.Int).Set(y),
		}
	}

	return points, nil
}

// RecoverSB recovers s*B from threshold number of shares s[i]*B using Lagrange interpolation
//
// The formula is:
//
//	w[i] = product(j != i, x[j]/(x[j] - x[i]))
//	s*B = sum(w[i] * s[i]*B)
func RecoverSB(shares []*PointShare) (*common.Point2D, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	prime := common.Q

	// Compute Lagrange interpolation weights w[i]
	weights := make([]*big.Int, len(shares))

	for j, shareJ := range shares {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for m, shareM := range shares {
			if j != m {
				// numerator = numerator * x[m] % prime
				numerator.Mul(numerator, shareM.X)
				numerator.Mod(numerator, prime)

				// denominator = denominator * (x[m] - x[j]) % prime
				diff := new(big.Int).Sub(shareM.X, shareJ.X)
				diff.Mod(diff, prime)
				denominator.Mul(denominator, diff)
				denominator.Mod(denominator, prime)
			}
		}

		// w[i] = numerator * denominator^(-1) % prime
		denominatorInv := new(big.Int).ModInverse(denominator, prime)
		if denominatorInv == nil {
			return nil, errors.New("failed to compute modular inverse")
		}

		wi := new(big.Int).Mul(numerator, denominatorInv)
		wi.Mod(wi, prime)
		weights[j] = wi
	}

	// Compute weighted sum: s*B = sum(w[i] * s[i]*B)
	sb := common.ZeroPoint

	for i, share := range shares {
		// Convert point to extended coordinates, multiply by weight, and add
		extendedPoint := common.Expand(&common.Point2D{
			X: new(big.Int).Set(share.Point.X),
			Y: new(big.Int).Set(share.Point.Y),
		})

		weightedPoint := common.PointMul(weights[i], extendedPoint)
		sb = common.PointAdd(sb, weightedPoint)
	}

	result := common.Unexpand(sb)
	return result, nil
}

// RecoverSecret recovers the original secret from threshold number of shares
func RecoverSecret(shares []*Share) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	prime := common.Q

	// Compute Lagrange interpolation weights w[i]
	weights := make([]*big.Int, len(shares))

	for j, shareJ := range shares {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for m, shareM := range shares {
			if j != m {
				// numerator = numerator * x[m] % prime
				numerator.Mul(numerator, shareM.X)
				numerator.Mod(numerator, prime)

				// denominator = denominator * (x[m] - x[j]) % prime
				diff := new(big.Int).Sub(shareM.X, shareJ.X)
				diff.Mod(diff, prime)
				denominator.Mul(denominator, diff)
				denominator.Mod(denominator, prime)
			}
		}

		// w[i] = numerator * denominator^(-1) % prime
		denominatorInv := new(big.Int).ModInverse(denominator, prime)
		if denominatorInv == nil {
			return nil, errors.New("failed to compute modular inverse")
		}

		wi := new(big.Int).Mul(numerator, denominatorInv)
		wi.Mod(wi, prime)
		weights[j] = wi
	}

	// Compute weighted sum: secret = sum(w[i] * y[i]) % prime
	secret := big.NewInt(0)

	for i, share := range shares {
		term := new(big.Int).Mul(weights[i], share.Y)
		secret.Add(secret, term)
		secret.Mod(secret, prime)
	}

	return secret, nil
}

// RecoverPointSecret recovers s*B from threshold number of point shares using Lagrange interpolation
// This is used when the shares are points on the elliptic curve (si * B) rather than scalar values
func RecoverPointSecret(shares []*PointShare) (*common.Point2D, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	prime := common.Q

	// Compute Lagrange interpolation weights w[i]
	weights := make([]*big.Int, len(shares))

	for j, shareJ := range shares {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for m, shareM := range shares {
			if j != m {
				// numerator = numerator * x[m] % prime
				numerator.Mul(numerator, shareM.X)
				numerator.Mod(numerator, prime)

				// denominator = denominator * (x[m] - x[j]) % prime
				diff := new(big.Int).Sub(shareM.X, shareJ.X)
				diff.Mod(diff, prime)
				denominator.Mul(denominator, diff)
				denominator.Mod(denominator, prime)
			}
		}

		// w[i] = numerator * denominator^(-1) % prime
		denominatorInv := new(big.Int).ModInverse(denominator, prime)
		if denominatorInv == nil {
			return nil, errors.New("failed to compute modular inverse")
		}

		wi := new(big.Int).Mul(numerator, denominatorInv)
		wi.Mod(wi, prime)
		weights[j] = wi
	}

	// Compute weighted sum: s*B = sum(w[i] * si*B)
	sb := common.ZeroPoint

	for i, share := range shares {
		// Convert point to extended coordinates, multiply by weight, and add
		extendedPoint := common.Expand(&common.Point2D{
			X: new(big.Int).Set(share.Point.X),
			Y: new(big.Int).Set(share.Point.Y),
		})

		weightedPoint := common.PointMul(weights[i], extendedPoint)
		sb = common.PointAdd(sb, weightedPoint)
	}

	result := common.Unexpand(sb)
	return result, nil
}
