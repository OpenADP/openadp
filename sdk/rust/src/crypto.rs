//! Cryptographic operations for OpenADP.
//!
//! This module implements the core cryptographic primitives used by OpenADP:
//! - Ed25519 elliptic curve operations
//! - Point compression/decompression 
//! - Shamir secret sharing
//! - HKDF key derivation
//! - Hash-to-point function H
//!
//! All operations are designed to be compatible with the Go and Python implementations.

use crate::{OpenADPError, Result};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use rug::{Integer, Complete};
use num_bigint::BigUint;
use num_traits::{Zero, One};
use hex;

// Ed25519 curve parameters (matching Go implementation)
lazy_static::lazy_static! {
    /// Base field Z_p where p = 2^255 - 19
    pub static ref P: BigUint = {
        let p_str = "57896044618658097711785492504343953926634992332820282019728792003956564819949";
        BigUint::parse_bytes(p_str.as_bytes(), 10).unwrap()
    };

    /// Curve constant d = -121665 * inv(121666) mod p
    pub static ref D: BigUint = {
        let inv121666 = mod_inverse(&BigUint::from(121666u32), &P);
        let mut d = &*P - &BigUint::from(121665u32); // -121665 mod p
        d = (&d * &inv121666) % &*P;
        d
    };

    /// Group order q = 2^252 + 27742317777372353535851937790883648493
    pub static ref Q: BigUint = {
        let q_str = "7237005577332262213973186563042994240857116359379907606001950938285454250989";
        BigUint::parse_bytes(q_str.as_bytes(), 10).unwrap()
    };

    /// Square root of -1 mod p
    pub static ref MODP_SQRT_M1: BigUint = {
        let exp = (&*P - 1u32) / 4u32;
        BigUint::from(2u32).modpow(&exp, &P)
    };

    /// Base point G
    pub static ref G: Point4D = {
        // Base point y-coordinate: 4/5 mod p
        let gy = (&BigUint::from(4u32) * &mod_inverse(&BigUint::from(5u32), &P)) % &*P;
        let gx = recover_x(&gy, 0).expect("Failed to recover base point X coordinate");
        expand(&Point2D { x: gx, y: gy })
    };

    /// Zero point (neutral element)
    pub static ref ZERO_POINT: Point4D = Point4D {
        x: BigUint::zero(),
        y: BigUint::one(),
        z: BigUint::one(),
        t: BigUint::zero(),
    };
}

/// 2D point representation for Ed25519
#[derive(Debug, Clone, PartialEq)]
pub struct Point2D {
    pub x: BigUint,
    pub y: BigUint,
}

impl Point2D {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self { x, y }
    }
}

/// 4D point representation for Ed25519 (extended coordinates)
#[derive(Debug, Clone, PartialEq)]
pub struct Point4D {
    pub x: BigUint,
    pub y: BigUint,
    pub z: BigUint,
    pub t: BigUint,
}

impl Point4D {
    pub fn new(x: BigUint, y: BigUint, z: BigUint, t: BigUint) -> Self {
        Self { x, y, z, t }
    }

    pub fn identity() -> Self {
        ZERO_POINT.clone()
    }
}

/// Expand converts a 2D point to extended 4D coordinates
pub fn expand(point: &Point2D) -> Point4D {
    let xy = (&point.x * &point.y) % &*P;
    Point4D {
        x: point.x.clone(),
        y: point.y.clone(),
        z: BigUint::one(),
        t: xy,
    }
}

/// Unexpand converts extended 4D coordinates back to 2D point
pub fn unexpand(point: &Point4D) -> Result<Point2D> {
    let z_inv = mod_inverse(&point.z, &P);
    let x = (&point.x * &z_inv) % &*P;
    let y = (&point.y * &z_inv) % &*P;
    Ok(Point2D { x, y })
}

/// SHA-256 hash function
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Modular inverse using Fermat's little theorem (for prime moduli)
pub fn mod_inverse(a: &BigUint, p: &BigUint) -> BigUint {
    // For prime p, a^(-1) = a^(p-2) mod p
    let exp = p - 2u32;
    a.modpow(&exp, p)
}

/// Add two points in extended coordinates (matching Go PointAdd)
pub fn point_add(p1: &Point4D, p2: &Point4D) -> Point4D {
    // A = (Y1 - X1) * (Y2 - X2)
    let a = ((&p1.y + &*P - &p1.x) * (&p2.y + &*P - &p2.x)) % &*P;
    
    // B = (Y1 + X1) * (Y2 + X2)
    let b = ((&p1.y + &p1.x) * (&p2.y + &p2.x)) % &*P;
    
    // C = 2 * T1 * T2 * d
    let c = (2u32 * &p1.t * &p2.t % &*P * &*D) % &*P;
    
    // D = 2 * Z1 * Z2
    let d = (2u32 * &p1.z * &p2.z) % &*P;
    
    // E, F, G, H = B - A, D - C, D + C, B + A
    let e = (&b + &*P - &a) % &*P;
    let f = (&d + &*P - &c) % &*P;
    let g = (&d + &c) % &*P;
    let h = (&b + &a) % &*P;
    
    // Return (E * F, G * H, F * G, E * H)
    Point4D {
        x: (&e * &f) % &*P,
        y: (&g * &h) % &*P,
        z: (&f * &g) % &*P,
        t: (&e * &h) % &*P,
    }
}

/// Multiply point by scalar using double-and-add (matching Go PointMul)
pub fn point_mul(s: &BigUint, p: &Point4D) -> Point4D {
    let mut q = ZERO_POINT.clone();
    let mut p_copy = p.clone();
    let mut s_copy = s.clone();
    
    while s_copy > BigUint::zero() {
        if s_copy.bit(0) {
            q = point_add(&q, &p_copy);
        }
        p_copy = point_add(&p_copy, &p_copy);
        s_copy >>= 1;
    }
    
    q
}

/// Multiply point by 8 (cofactor clearing, matching Go pointMul8)
pub fn point_mul8(p: &Point4D) -> Point4D {
    // Multiply by 8 = 2^3, so we double 3 times
    let mut result = point_add(p, p);          // 2P
    result = point_add(&result, &result);      // 4P
    result = point_add(&result, &result);      // 8P
    result
}

/// Check if two points are equal in projective coordinates
pub fn point_equal(p1: &Point4D, p2: &Point4D) -> bool {
    // x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    let left = (&p1.x * &p2.z) % &*P;
    let right = (&p2.x * &p1.z) % &*P;
    if left != right {
        return false;
    }
    
    let left = (&p1.y * &p2.z) % &*P;
    let right = (&p2.y * &p1.z) % &*P;
    left == right
}

/// Recover x-coordinate from y and sign bit (matching Go recoverX)
pub fn recover_x(y: &BigUint, sign: u8) -> Option<BigUint> {
    if y >= &*P {
        return None;
    }
    
    // x^2 = (y^2 - 1) / (d * y^2 + 1)
    let y2 = (y * y) % &*P;
    
    let numerator = (&y2 + &*P - 1u32) % &*P;
    let denominator = ((&*D * &y2) + 1u32) % &*P;
    
    let denominator_inv = mod_inverse(&denominator, &P);
    let x2 = (&numerator * &denominator_inv) % &*P;
    
    if x2.is_zero() {
        return if sign != 0 { None } else { Some(BigUint::zero()) };
    }
    
    // Compute square root of x2
    let exp = (&*P + 3u32) / 8u32;
    let mut x = x2.modpow(&exp, &P);
    
    // Check if x^2 == x2
    let x_squared = (&x * &x) % &*P;
    if x_squared != x2 {
        x = (&x * &*MODP_SQRT_M1) % &*P;
    }
    
    // Verify again
    let x_squared = (&x * &x) % &*P;
    if x_squared != x2 {
        return None;
    }
    
    // Check sign
    if x.bit(0) != (sign != 0) {
        x = &*P - &x;
    }
    
    Some(x)
}

/// Compress a point to 32 bytes (matching Go PointCompress)
pub fn point_compress(p: &Point4D) -> Result<Vec<u8>> {
    let z_inv = mod_inverse(&p.z, &P);
    let x = (&p.x * &z_inv) % &*P;
    let mut y = (&p.y * &z_inv) % &*P;
    
    // Set sign bit
    if x.bit(0) {
        y.set_bit(255, true);
    }
    
    // Convert to little-endian 32 bytes
    let mut result = vec![0u8; 32];
    let y_bytes = y.to_bytes_le();
    let copy_len = std::cmp::min(y_bytes.len(), 32);
    result[..copy_len].copy_from_slice(&y_bytes[..copy_len]);
    
    Ok(result)
}

/// Decompress 32 bytes to a point (matching Go PointDecompress)
pub fn point_decompress(data: &[u8]) -> Result<Point4D> {
    if data.len() != 32 {
        return Err(OpenADPError::PointOperation("Invalid input length for decompression".to_string()));
    }
    
    // Convert from little-endian
    let mut y = BigUint::zero();
    for i in 0..32 {
        for bit in 0..8 {
            if (data[i] >> bit) & 1 == 1 {
                y.set_bit((i * 8 + bit) as u64, true);
            }
        }
    }
    
    let sign = if y.bit(255) { 1 } else { 0 };
    y.set_bit(255, false); // Clear sign bit
    
    let x = recover_x(&y, sign)
        .ok_or_else(|| OpenADPError::PointOperation("Invalid point".to_string()))?;
    
    let xy = (&x * &y) % &*P;
    let point = Point4D {
        x,
        y,
        z: BigUint::one(),
        t: xy,
    };
    
    // Validate the decompressed point
    if !is_valid_point(&point) {
        return Err(OpenADPError::PointOperation("Invalid point: failed validation".to_string()));
    }
    
    Ok(point)
}

/// Check if a point is valid using Ed25519 cofactor clearing
pub fn is_valid_point(p: &Point4D) -> bool {
    // Check that the point is not the zero point
    if point_equal(p, &ZERO_POINT) {
        return false;
    }
    
    // Ed25519 point validation using cofactor clearing:
    // A valid point P should satisfy: 8*P is not the zero point
    let eight_p = point_mul8(p);
    !point_equal(&eight_p, &ZERO_POINT)
}

/// Add 16-bit length prefix to data (matching Go prefixed)
pub fn prefixed(data: &[u8]) -> Vec<u8> {
    let l = data.len();
    if l >= (1 << 16) {
        panic!("Input string too long");
    }
    let mut result = Vec::with_capacity(data.len() + 2);
    result.push(l as u8);           // Low byte
    result.push((l >> 8) as u8);    // High byte
    result.extend_from_slice(data);
    result
}

/// Reverse bytes for little-endian conversion
fn reverse_bytes(data: &[u8]) -> Vec<u8> {
    data.iter().rev().copied().collect()
}

/// Hash-to-point function H (matching Go H function exactly)
pub fn H(uid: &[u8], did: &[u8], bid: &[u8], pin: &[u8]) -> Result<Point4D> {
    println!("🔍 Rust H DEBUG: uid={:?}, did={:?}, bid={:?}, pin={:?}", uid, did, bid, pin);
    
    // Concatenate all inputs with length prefixes (matching Go implementation)
    let mut data = prefixed(uid);
    data.extend_from_slice(&prefixed(did));
    data.extend_from_slice(&prefixed(bid));
    data.extend_from_slice(pin);
    
    println!("🔍 Rust H DEBUG: combined data={}", hex::encode(&data));
    
    // Hash and convert to point
    let hash = sha256_hash(&data);
    println!("🔍 Rust H DEBUG: hash_bytes={}", hex::encode(&hash));
    
    // Convert hash to big integer and extract sign bit (matching Go)
    let y_base_full = BigUint::from_bytes_le(&hash);
    println!("🔍 Rust H DEBUG: y_base_full (from LE): {:064x}", y_base_full);
    
    let sign = if y_base_full.bit(255) { 1 } else { 0 };
    let mut y_base = y_base_full.clone();
    y_base.set_bit(255, false); // Clear sign bit
    
    println!("🔍 Rust H DEBUG: sign={}, y_base_cleared={:064x}", sign, y_base);
    
    for counter in 0..1000 {
        // XOR with counter to find valid point
        let y = &y_base ^ BigUint::from(counter as u32);
        println!("🔍 Rust H DEBUG: counter={}, y={:064x}", counter, y);
        
        if let Some(x) = recover_x(&y, sign) {
            println!("🔍 Rust H DEBUG: Found valid point at counter={}, x={}, y={}", 
                counter, hex::encode(&x.to_bytes_le()), hex::encode(&y.to_bytes_le()));
            
            // Force the point to be in a group of order q (multiply by 8)
            let p = expand(&Point2D { x, y });
            let p = point_mul8(&p);
            
            if is_valid_point(&p) {
                println!("🔍 Rust H DEBUG: Final point: x={}, y={}", 
                    hex::encode(&p.x.to_bytes_le()), hex::encode(&p.y.to_bytes_le()));
                return Ok(p);
            }
        }
    }
    
    // Fallback to base point if no valid point found
    println!("🔍 Rust H DEBUG: No valid point found, using base point");
    Ok(G.clone())
}

/// Derive encryption key from point using HKDF (matching Go DeriveEncKey)
pub fn derive_enc_key(point: &Point4D) -> Result<Vec<u8>> {
    let point_bytes = point_compress(point)?;
    
    // Use HKDF with proper salt and info to match Go implementation
    let salt = b"OpenADP-EncKey-v1";
    let info = b"AES-256-GCM";
    
    let hk = Hkdf::<Sha256>::new(Some(salt), &point_bytes);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| OpenADPError::Crypto(format!("HKDF expansion failed: {}", e)))?;
    
    Ok(okm.to_vec())
}

// Large prime for Shamir secret sharing - using Go's Q value
// This is the order of the Ed25519 curve
const Q_HEX: &str = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

/// Shamir secret sharing implementation using finite field arithmetic with rug big integers
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Get the prime modulus Q as a rug Integer
    pub fn get_q() -> Integer {
        Integer::from_str_radix(Q_HEX, 16).unwrap()
    }

    /// Generate a cryptographically secure random number less than Q
    fn random_mod_q() -> Integer {
        let q = Self::get_q();
        let mut rng = OsRng;
        
        // Generate a random integer with the same bit length as Q
        let bit_len = q.significant_bits();
        let byte_len = (bit_len + 7) / 8;
        
        loop {
            let mut bytes = vec![0u8; byte_len as usize];
            rng.fill_bytes(&mut bytes);
            
            let random_int = Integer::from_digits(&bytes, rug::integer::Order::MsfBe);
            if random_int < q {
                return random_int;
            }
        }
    }

    /// Split integer secret into shares (matches Go implementation exactly)
    pub fn split_secret(secret: &Integer, threshold: usize, num_shares: usize) -> Result<Vec<(usize, Integer)>> {
        if threshold == 0 || threshold > num_shares {
            return Err(OpenADPError::SecretSharing("Invalid threshold".to_string()));
        }
        
        let q = Self::get_q();
        
        if *secret >= q {
            return Err(OpenADPError::SecretSharing("Secret too large for field".to_string()));
        }
        
        // Generate random coefficients for polynomial f(x) = a0 + a1*x + a2*x^2 + ...
        // where a0 = secret
        let mut coefficients = vec![secret.clone()];
        
        for _ in 1..threshold {
            // DEBUG: Set r = 1 for deterministic debugging (remove this later)
            coefficients.push(Integer::from(1));  // Self::random_mod_q()
        }
        
        // Evaluate polynomial at x = 1, 2, ..., num_shares
        let mut shares = Vec::new();
        for x in 1..=num_shares {
            let x_int = Integer::from(x);
            let mut y = Integer::new();
            let mut x_power = Integer::from(1);
            
            for coeff in &coefficients {
                // y = (y + coeff * x_power) % q
                let term = (coeff * &x_power).complete() % &q;
                y = (&y + &term).complete() % &q;
                // x_power = (x_power * x) % q
                x_power = (&x_power * &x_int).complete() % &q;
            }
            
            shares.push((x, y));
        }
        
        Ok(shares)
    }
    
    /// Recover integer secret from shares (matches Go implementation exactly)
    pub fn recover_secret(shares: Vec<(usize, Integer)>) -> Result<Integer> {
        if shares.is_empty() {
            return Err(OpenADPError::SecretSharing("No shares provided".to_string()));
        }
        
        let q = Self::get_q();
        let mut secret = Integer::new();
        
        // Convert x coordinates to integers
        let int_shares: Vec<(Integer, Integer)> = shares.into_iter()
            .map(|(x, y)| (Integer::from(x), y))
            .collect();
        
        // Lagrange interpolation to find f(0)
        for (i, (xi, yi)) in int_shares.iter().enumerate() {
            // Compute Lagrange basis polynomial Li(0)
            let mut numerator = Integer::from(1);
            let mut denominator = Integer::from(1);
            
            for (j, (xj, _)) in int_shares.iter().enumerate() {
                if i != j {
                    // numerator = numerator * (0 - xj) = numerator * (-xj) = numerator * (q - xj)
                    let neg_xj = Integer::from(&q - xj);
                    numerator = Integer::from(&numerator * &neg_xj) % &q;
                    // denominator = denominator * (xi - xj)
                    let xi_clone = xi.clone();
                    let xj_clone = xj.clone();
                    let diff = if &xi_clone >= &xj_clone {
                        Integer::from(&xi_clone - &xj_clone)
                    } else {
                        let xj_minus_xi = Integer::from(&xj_clone - &xi_clone);
                        Integer::from(&q - &xj_minus_xi)
                    };
                    denominator = Integer::from(&denominator * &diff) % &q;
                }
            }
            
            // Compute Li(0) = numerator / denominator (mod q)
            let denominator_inv = denominator.invert(&q)
                .map_err(|_| OpenADPError::SecretSharing("Cannot invert denominator".to_string()))?;
            let li_0 = (&numerator * &denominator_inv).complete() % &q;
            
            // Add yi * Li(0) to result
            let term = (yi * &li_0).complete() % &q;
            secret = (&secret + &term).complete() % &q;
        }
        
        Ok(secret)
    }

    /// Split secret into shares using polynomial evaluation over finite field
    pub fn split_secret_bytes(secret: &[u8], threshold: usize, num_shares: usize) -> Result<Vec<(usize, Vec<u8>)>> {
        if threshold == 0 || threshold > num_shares {
            return Err(OpenADPError::SecretSharing("Invalid threshold".to_string()));
        }
        
        // Convert bytes to big integer
        let secret_int = Integer::from_digits(secret, rug::integer::Order::MsfBe);
        
        // Split the integer secret
        let int_shares = Self::split_secret(&secret_int, threshold, num_shares)?;
        
        // Convert back to bytes
        let mut byte_shares = Vec::new();
        for (x, y) in int_shares {
            let y_bytes = y.to_digits::<u8>(rug::integer::Order::MsfBe);
            byte_shares.push((x, y_bytes));
        }
        
        Ok(byte_shares)
    }
    
    /// Recover secret from byte shares
    pub fn recover_secret_bytes(shares: Vec<(usize, Vec<u8>)>) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(OpenADPError::SecretSharing("No shares provided".to_string()));
        }
        
        // Convert bytes to integers
        let int_shares = shares.into_iter()
            .map(|(x, y_bytes)| {
                let y = Integer::from_digits(&y_bytes, rug::integer::Order::MsfBe);
                (x, y)
            })
            .collect();
        
        // Recover integer secret
        let secret_int = Self::recover_secret(int_shares)?;
        
        // Convert back to bytes
        let secret_bytes = secret_int.to_digits::<u8>(rug::integer::Order::MsfBe);
        
        Ok(secret_bytes)
    }
}

/// Point share for point-based secret sharing
pub struct PointShare {
    pub x: usize,
    pub point: Point4D,
}

impl PointShare {
    pub fn new(x: usize, point: Point4D) -> Self {
        Self { x, point }
    }
}

/// Recover point secret from point shares using Lagrange interpolation
pub fn recover_point_secret(point_shares: Vec<PointShare>) -> Result<Point4D> {
    if point_shares.is_empty() {
        return Err(OpenADPError::SecretSharing("No point shares provided".to_string()));
    }
    
    let q = &*Q;
    let mut secret_point = ZERO_POINT.clone();
    
    // Lagrange interpolation in point space
    for (i, share_i) in point_shares.iter().enumerate() {
        let xi = BigUint::from(share_i.x);
        
        // Compute Lagrange basis polynomial Li(0)
        let mut numerator = BigUint::one();
        let mut denominator = BigUint::one();
        
        for (j, share_j) in point_shares.iter().enumerate() {
            if i != j {
                let xj = BigUint::from(share_j.x);
                
                // numerator = numerator * (0 - xj) = numerator * (-xj) = numerator * (q - xj)
                let neg_xj = (q + q - &xj) % q; // Equivalent to q - xj
                numerator = (&numerator * &neg_xj) % q;
                
                // denominator = denominator * (xi - xj)
                let diff = if &xi >= &xj {
                    (&xi - &xj) % q
                } else {
                    (q + &xi - &xj) % q
                };
                denominator = (&denominator * &diff) % q;
            }
        }
        
        // Compute Li(0) = numerator / denominator (mod q)
        let denominator_inv = mod_inverse(&denominator, q);
        let li_0 = (&numerator * &denominator_inv) % q;
        
        // Add Li(0) * Pi to result
        let term_point = point_mul(&li_0, &share_i.point);
        secret_point = point_add(&secret_point, &term_point);
    }
    
    Ok(secret_point)
}

/// Ed25519 operations wrapper
pub struct Ed25519;

impl Ed25519 {
    pub fn H(uid: &[u8], did: &[u8], bid: &[u8], pin: &[u8]) -> Result<Point4D> {
        H(uid, did, bid, pin)
    }

    pub fn scalar_mult(scalar: &[u8], point: &Point4D) -> Result<Point4D> {
        let scalar_bigint = BigUint::from_bytes_le(scalar);
        Ok(point_mul(&scalar_bigint, point))
    }

    pub fn point_add(p1: &Point4D, p2: &Point4D) -> Result<Point4D> {
        Ok(point_add(p1, p2))
    }

    pub fn compress(point: &Point4D) -> Result<Vec<u8>> {
        point_compress(point)
    }

    pub fn decompress(data: &[u8]) -> Result<Point4D> {
        point_decompress(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_operations() {
        // Test basic point operations
        let p1 = G.clone();
        let p2 = point_add(&p1, &p1);
        
        // Test that 2*G != G
        assert!(!point_equal(&p1, &p2));
        
        // Test point multiplication
        let scalar = BigUint::from(2u32);
        let p3 = point_mul(&scalar, &p1);
        assert!(point_equal(&p2, &p3));
    }

    #[test]
    fn test_hash_functions() {
        let data = b"test data";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_H() {
        let uid = b"test-user";
        let did = b"test-device";
        let bid = b"test-backup";
        let pin = b"12";
        
        let point = H(uid, did, bid, pin).unwrap();
        assert!(is_valid_point(&point));
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let secret = Integer::from(12345);
        let threshold = 3;
        let num_shares = 5;
        
        let shares = ShamirSecretSharing::split_secret(&secret, threshold, num_shares).unwrap();
        assert_eq!(shares.len(), num_shares);
        
        // Test recovery with minimum threshold
        let recovery_shares = shares.into_iter().take(threshold).collect();
        let recovered = ShamirSecretSharing::recover_secret(recovery_shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_key_derivation() {
        let point = G.clone();
        let key = derive_enc_key(&point).unwrap();
        assert_eq!(key.len(), 32);
    }
} 
