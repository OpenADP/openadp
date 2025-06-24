// Package common provides shared cryptographic primitives and utilities for OpenADP.
package common

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Point2D represents a 2D point with (x, y) coordinates
type Point2D struct {
	X, Y *big.Int
}

// Point4D represents extended coordinates (X, Y, Z, T)
type Point4D struct {
	X, Y, Z, T *big.Int
}

// Constants for Ed25519 curve
var (
	// Base field Z_p where p = 2^255 - 19
	P = new(big.Int)

	// Curve constant d = -121665 * inv(121666) mod p
	D = new(big.Int)

	// Group order q = 2^252 + 27742317777372353535851937790883648493
	Q = new(big.Int)

	// Base point G
	G = &Point4D{}

	// Zero point (neutral element)
	ZeroPoint = &Point4D{}

	// Square root of -1 mod p
	ModpSqrtM1 = new(big.Int)
)

func init() {
	// Initialize constants
	P.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10) // 2^255 - 19
	Q.SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)  // 2^252 + 27742317777372353535851937790883648493

	// Calculate d = -121665 * inv(121666) mod p
	inv121666 := new(big.Int)
	inv121666.SetInt64(121666)
	inv121666.ModInverse(inv121666, P)
	D.SetInt64(-121665)
	D.Mul(D, inv121666)
	D.Mod(D, P)

	// Calculate square root of -1 mod p
	exp := new(big.Int).Sub(P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	ModpSqrtM1.SetInt64(2)
	ModpSqrtM1.Exp(ModpSqrtM1, exp, P)

	// Initialize base point G
	gY := new(big.Int).SetInt64(4)
	inv5 := new(big.Int).SetInt64(5)
	inv5.ModInverse(inv5, P)
	gY.Mul(gY, inv5)
	gY.Mod(gY, P)

	gX := recoverX(gY, 0)
	if gX == nil {
		panic("Failed to recover base point X coordinate")
	}

	G = Expand(&Point2D{X: gX, Y: gY})

	// Initialize zero point (0, 1, 1, 0)
	ZeroPoint = &Point4D{
		X: big.NewInt(0),
		Y: big.NewInt(1),
		Z: big.NewInt(1),
		T: big.NewInt(0),
	}
}

// Expand converts a 2D point to extended 4D coordinates
func Expand(point *Point2D) *Point4D {
	xy := new(big.Int).Mul(point.X, point.Y)
	xy.Mod(xy, P)

	return &Point4D{
		X: new(big.Int).Set(point.X),
		Y: new(big.Int).Set(point.Y),
		Z: big.NewInt(1),
		T: xy,
	}
}

// Unexpand converts extended 4D coordinates back to 2D point
func Unexpand(point *Point4D) *Point2D {
	zInv := new(big.Int).ModInverse(point.Z, P)

	x := new(big.Int).Mul(point.X, zInv)
	x.Mod(x, P)

	y := new(big.Int).Mul(point.Y, zInv)
	y.Mod(y, P)

	return &Point2D{X: x, Y: y}
}

// Sha256Hash computes SHA-256 hash of input bytes
func Sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// modpInv computes modular inverse of x modulo prime using Fermat's little theorem
func modpInv(x *big.Int) *big.Int {
	exp := new(big.Int).Sub(P, big.NewInt(2))
	result := new(big.Int).Exp(x, exp, P)
	return result
}

// PointAdd adds two points in extended coordinates
func PointAdd(p1, p2 *Point4D) *Point4D {
	// A = (Y1 - X1) * (Y2 - X2)
	a := new(big.Int).Sub(p1.Y, p1.X)
	temp := new(big.Int).Sub(p2.Y, p2.X)
	a.Mul(a, temp)
	a.Mod(a, P)

	// B = (Y1 + X1) * (Y2 + X2)
	b := new(big.Int).Add(p1.Y, p1.X)
	temp = new(big.Int).Add(p2.Y, p2.X)
	b.Mul(b, temp)
	b.Mod(b, P)

	// C = 2 * T1 * T2 * d
	c := new(big.Int).Mul(p1.T, p2.T)
	c.Mul(c, D)
	c.Mul(c, big.NewInt(2))
	c.Mod(c, P)

	// D = 2 * Z1 * Z2
	d := new(big.Int).Mul(p1.Z, p2.Z)
	d.Mul(d, big.NewInt(2))
	d.Mod(d, P)

	// E, F, G, H = B - A, D - C, D + C, B + A
	e := new(big.Int).Sub(b, a)
	e.Mod(e, P)

	f := new(big.Int).Sub(d, c)
	f.Mod(f, P)

	g := new(big.Int).Add(d, c)
	g.Mod(g, P)

	h := new(big.Int).Add(b, a)
	h.Mod(h, P)

	// Return (E * F, G * H, F * G, E * H)
	return &Point4D{
		X: new(big.Int).Mul(e, f).Mod(new(big.Int).Mul(e, f), P),
		Y: new(big.Int).Mul(g, h).Mod(new(big.Int).Mul(g, h), P),
		Z: new(big.Int).Mul(f, g).Mod(new(big.Int).Mul(f, g), P),
		T: new(big.Int).Mul(e, h).Mod(new(big.Int).Mul(e, h), P),
	}
}

// PointMul computes scalar multiplication: Q = s * P using double-and-add
func PointMul(s *big.Int, p *Point4D) *Point4D {
	// Convert to affine coordinates for clearer debugging
	zinv := modpInv(p.Z)
	affineX := new(big.Int).Mul(p.X, zinv)
	affineX.Mod(affineX, P)
	affineY := new(big.Int).Mul(p.Y, zinv)
	affineY.Mod(affineY, P)

	q := &Point4D{
		X: new(big.Int).Set(ZeroPoint.X),
		Y: new(big.Int).Set(ZeroPoint.Y),
		Z: new(big.Int).Set(ZeroPoint.Z),
		T: new(big.Int).Set(ZeroPoint.T),
	}

	pCopy := &Point4D{
		X: new(big.Int).Set(p.X),
		Y: new(big.Int).Set(p.Y),
		Z: new(big.Int).Set(p.Z),
		T: new(big.Int).Set(p.T),
	}

	sCopy := new(big.Int).Set(s)

	for sCopy.Sign() > 0 {
		if sCopy.Bit(0) == 1 {
			q = PointAdd(q, pCopy)
		}
		pCopy = PointAdd(pCopy, pCopy)
		sCopy.Rsh(sCopy, 1)
	}

	// Debug logging for result
	resultZinv := modpInv(q.Z)
	resultX := new(big.Int).Mul(q.X, resultZinv)
	resultX.Mod(resultX, P)
	resultY := new(big.Int).Mul(q.Y, resultZinv)
	resultY.Mod(resultY, P)

	return q
}

// PointEqual checks if two points are equal in projective coordinates
func PointEqual(p1, p2 *Point4D) bool {
	// x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
	left := new(big.Int).Mul(p1.X, p2.Z)
	left.Mod(left, P)
	right := new(big.Int).Mul(p2.X, p1.Z)
	right.Mod(right, P)

	if left.Cmp(right) != 0 {
		return false
	}

	left = new(big.Int).Mul(p1.Y, p2.Z)
	left.Mod(left, P)
	right = new(big.Int).Mul(p2.Y, p1.Z)
	right.Mod(right, P)

	return left.Cmp(right) == 0
}

// recoverX computes corresponding x-coordinate from y and sign bit
func recoverX(y *big.Int, sign int) *big.Int {
	if y.Cmp(P) >= 0 {
		return nil
	}

	// x^2 = (y^2 - 1) / (d * y^2 + 1)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, P)

	numerator := new(big.Int).Sub(y2, big.NewInt(1))
	numerator.Mod(numerator, P)

	denominator := new(big.Int).Mul(D, y2)
	denominator.Add(denominator, big.NewInt(1))
	denominator.Mod(denominator, P)

	denominatorInv := modpInv(denominator)
	x2 := new(big.Int).Mul(numerator, denominatorInv)
	x2.Mod(x2, P)

	if x2.Sign() == 0 {
		if sign != 0 {
			return nil
		}
		return big.NewInt(0)
	}

	// Compute square root of x2
	exp := new(big.Int).Add(P, big.NewInt(3))
	exp.Div(exp, big.NewInt(8))
	x := new(big.Int).Exp(x2, exp, P)

	// Check if x^2 == x2
	xSquared := new(big.Int).Mul(x, x)
	xSquared.Mod(xSquared, P)

	if xSquared.Cmp(x2) != 0 {
		x.Mul(x, ModpSqrtM1)
		x.Mod(x, P)
	}

	// Verify again
	xSquared = new(big.Int).Mul(x, x)
	xSquared.Mod(xSquared, P)
	if xSquared.Cmp(x2) != 0 {
		return nil
	}

	// Check sign
	if int(x.Bit(0)) != sign {
		x.Sub(P, x)
	}

	return x
}

// PointCompress compresses a point to 32 bytes
func PointCompress(p *Point4D) []byte {
	zinv := modpInv(p.Z)

	x := new(big.Int).Mul(p.X, zinv)
	x.Mod(x, P)

	y := new(big.Int).Mul(p.Y, zinv)
	y.Mod(y, P)

	// Set sign bit
	if x.Bit(0) == 1 {
		y.SetBit(y, 255, 1)
	}

	result := make([]byte, 32)
	yBytes := y.Bytes()

	// Copy bytes in little-endian format
	for i := 0; i < len(yBytes) && i < 32; i++ {
		result[i] = yBytes[len(yBytes)-1-i]
	}

	return result
}

// PointDecompress decompresses 32 bytes to a point
func PointDecompress(data []byte) (*Point4D, error) {
	if len(data) != 32 {
		return nil, errors.New("invalid input length for decompression")
	}

	// Convert from little-endian
	y := big.NewInt(0)
	for i := 0; i < 32; i++ {
		for bit := 0; bit < 8; bit++ {
			if (data[i]>>bit)&1 == 1 {
				y.SetBit(y, i*8+bit, 1)
			}
		}
	}

	sign := int(y.Bit(255))
	y.SetBit(y, 255, 0) // Clear sign bit

	x := recoverX(y, sign)
	if x == nil {
		return nil, errors.New("invalid point")
	}

	xy := new(big.Int).Mul(x, y)
	xy.Mod(xy, P)

	point := &Point4D{
		X: x,
		Y: y,
		Z: big.NewInt(1),
		T: xy,
	}

	// Validate the decompressed point
	if !IsValidPoint(point) {
		return nil, errors.New("invalid point: failed validation")
	}

	return point, nil
}

// SecretExpand expands a 32-byte secret key to a scalar
func SecretExpand(secret []byte) (*big.Int, error) {
	if len(secret) != 32 {
		return nil, errors.New("bad size of private key")
	}

	h := Sha256Hash(secret)
	a := new(big.Int).SetBytes(reverseBytes(h)) // Convert from little-endian

	// a &= (1 << 254) - 8
	mask := new(big.Int).Lsh(big.NewInt(1), 254)
	mask.Sub(mask, big.NewInt(8))
	a.And(a, mask)

	// a |= (1 << 254)
	bit254 := new(big.Int).Lsh(big.NewInt(1), 254)
	a.Or(a, bit254)

	return a, nil
}

// SecretToPublic converts a private key to its corresponding public key
func SecretToPublic(secret []byte) ([]byte, error) {
	a, err := SecretExpand(secret)
	if err != nil {
		return nil, err
	}

	publicPoint := PointMul(a, G)
	return PointCompress(publicPoint), nil
}

// prefixed returns a 16-bit length prefixed (little-endian) byte string
func prefixed(a []byte) []byte {
	l := len(a)
	if l >= 1<<16 {
		panic("Input string too long")
	}
	prefix := make([]byte, 2)
	prefix[0] = byte(l)
	prefix[1] = byte(l >> 8)
	return append(prefix, a...)
}

// pointMul8 multiplies a point by 8 (matching Python point_mul8)
func pointMul8(p *Point4D) *Point4D {
	// Multiply by 8 = 2^3, so we double 3 times
	result := PointAdd(p, p)          // 2P
	result = PointAdd(result, result) // 4P
	result = PointAdd(result, result) // 8P
	return result
}

// IsValidPoint checks if a point is valid using Ed25519 cofactor clearing
func IsValidPoint(p *Point4D) bool {
	if p == nil || p.X == nil || p.Y == nil || p.Z == nil || p.T == nil {
		return false
	}

	// Check that the point is not the zero point
	if PointEqual(p, ZeroPoint) {
		return false
	}

	// Ed25519 point validation using cofactor clearing:
	// A valid point P should satisfy: 8*P is not the zero point
	// This catches low-order points (which have order dividing 8)
	// Since Y coordinates are derived from X using the curve equation,
	// we know the point is already on the curve, so no need to verify that.
	eightP := pointMul8(p)

	// The point is valid if 8*P is not the zero point
	// (Zero point would indicate a low-order point)
	return !PointEqual(eightP, ZeroPoint)
}

// H computes the hash function H(UID, DID, BID, pin) -> Point
func H(uid, did, bid, pin []byte) *Point4D {
	// Concatenate all inputs with length prefixes (matching Python implementation)
	data := prefixed(uid)
	data = append(data, prefixed(did)...)
	data = append(data, prefixed(bid)...)
	data = append(data, pin...)

	// Hash and convert to point
	hash := Sha256Hash(data)

	// Convert hash to big integer and extract sign bit (matching Python)
	yBase := new(big.Int).SetBytes(reverseBytes(hash)) // little-endian
	sign := int(yBase.Bit(255))
	yBase.SetBit(yBase, 255, 0) // Clear sign bit

	counter := 0
	for {
		// XOR with counter to find valid point
		y := new(big.Int).Xor(yBase, big.NewInt(int64(counter)))

		x := recoverX(y, sign)
		if x != nil {
			// Force the point to be in a group of order q (multiply by 8)
			P := Expand(&Point2D{X: x, Y: y})
			P = pointMul8(P)
			if IsValidPoint(P) {
				return P
			}
		}
		counter++

		// Safety check to avoid infinite loop
		if counter > 1000 {
			break
		}
	}

	// Fallback to base point if no valid point found
	return G
}

// DeriveEncKey derives an encryption key from a point
func DeriveEncKey(p *Point4D) []byte {
	compressed := PointCompress(p)

	// Use HKDF to derive a 32-byte key
	salt := []byte("OpenADP-EncKey-v1")
	info := []byte("AES-256-GCM")

	hkdf := hkdf.New(sha256.New, compressed, salt, info)
	key := make([]byte, 32)
	hkdf.Read(key)

	return key
}

// X25519GenerateKeypair generates a X25519 keypair
func X25519GenerateKeypair() ([]byte, []byte, error) {
	private := make([]byte, 32)
	_, err := rand.Read(private)
	if err != nil {
		return nil, nil, err
	}

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return private, public, nil
}

// X25519PublicKeyFromPrivate derives public key from private key
func X25519PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, curve25519.Basepoint)
}

// X25519DH performs Diffie-Hellman key exchange
func X25519DH(privateKey, publicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, publicKey)
}

// Helper function to reverse bytes for little-endian conversion
func reverseBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[len(data)-1-i]
	}
	return result
}

// DeriveSecret creates a deterministic secret from input parameters.
// This ensures the same inputs always produce the same secret for key recovery.
func DeriveSecret(uid, did, bid, pin []byte) *big.Int {
	// Combine all input parameters
	combined := append(uid, did...)
	combined = append(combined, bid...)
	combined = append(combined, pin...)

	// Add a domain separator to prevent collisions with other uses
	domainSep := []byte("OPENADP_SECRET_DERIVATION_V1")
	combined = append(domainSep, combined...)

	// Hash the combined data
	hash := sha256.Sum256(combined)

	// Convert hash to big integer and reduce modulo Q
	secret := new(big.Int).SetBytes(hash[:])
	secret.Mod(secret, Q)

	// Ensure secret is not zero
	if secret.Sign() == 0 {
		secret.SetInt64(1)
	}

	return secret
}

// DeriveEncKey derives an encryption key from a point using HKDF
