#!/usr/bin/env python3
"""
OpenADP Cryptographic Functions

This module implements Ed25519-based cryptographic operations for the OpenADP
system, including point arithmetic, compression/decompression, and key derivation.

Based on RFC 8032: https://datatracker.ietf.org/doc/html/rfc8032
"""

import hashlib
from typing import Tuple, Optional, Union
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import nacl.public
import nacl.encoding

# Type definitions for clarity
Point2D = Tuple[int, int]  # (x, y) coordinates
Point4D = Tuple[int, int, int, int]  # Extended coordinates (X, Y, Z, T)
PointAny = Union[Point2D, Point4D]

# Convert (x, y) to the expanded form (x, y, 1, x*y)
def expand(point: Point2D) -> Point4D:
    """Convert a 2D point to extended 4D coordinates."""
    x, y = point
    return (x, y, 1, x * y % p)


def unexpand(point: Point4D) -> Point2D:
    """Convert extended 4D coordinates back to 2D point."""
    x, y, z, t = point
    z_inv = modp_inv(z)
    return (x * z_inv % p, y * z_inv % p)


def sha256(s: bytes) -> bytes:
    """Compute SHA-256 hash of input bytes."""
    return hashlib.sha256(s).digest()


# Base field Z_p
p: int = 2**255 - 19


def modp_inv(x: int, prime: int = p) -> int:
    """Compute modular inverse of x modulo prime using Fermat's little theorem."""
    return pow(x, prime - 2, prime)


# Curve constant
d: int = -121665 * modp_inv(121666) % p

# Group order
q: int = 2**252 + 27742317777372353535851937790883648493

## Point operations

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

def point_mul8(P: Point4D) -> Point4D:
    """Multiply a point by 8 quickly using repeated doubling."""
    P2 = point_add(P, P)
    P4 = point_add(P2, P2)
    return point_add(P4, P4)


def point_valid(P: Point4D) -> bool:
    """Check if a point is valid (non-zero and has correct order)."""
    if point_equal(P, zero_point):
        return False
    return point_equal(point_mul(q, P), zero_point)


def point_add(P: Point4D, Q: Point4D) -> Point4D:
    """Add two points in extended coordinates."""
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def point_mul(s: int, P: Point4D) -> Point4D:
    """Compute scalar multiplication: Q = s * P using double-and-add."""
    Q = zero_point
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def point_equal(P: Point4D, Q: Point4D) -> bool:
    """Check if two points are equal in projective coordinates."""
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True

## Point compression functions

# Square root of -1
modp_sqrt_m1: int = pow(2, (p - 1) // 4, p)


def recover_x(y: int, sign: int) -> Optional[int]:
    """
    Compute corresponding x-coordinate from y and sign bit.
    
    Args:
        y: Y coordinate
        sign: Sign bit (0 or 1)
        
    Returns:
        X coordinate if valid, None if no valid x exists
    """
    if y >= p:
        return None
    
    x2 = (y * y - 1) * modp_inv(d * y * y + 1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x


# Base point
g_y: int = 4 * modp_inv(5) % p
g_x: int = recover_x(g_y, 0)
G: Point4D = expand((g_x, g_y))

# The mathematician Edwards believes angles should be measured clockwise from
# the Y axis rather than counter-clockwise from the X axis, and so he decided
# just for his Edwards curve to ignore thousands of years of mathematical
# precedence.  This is why the point corresponding to 0 is at (0, 1), rather
# than (1, 0).  Ugh...
zero_point: Point4D = (0, 1, 1, 0)  # Neutral element


def point_compress(P: Point4D) -> bytes:
    """Compress a point to 32 bytes."""
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(s: bytes) -> Optional[Point4D]:
    """Decompress 32 bytes to a point, or None if invalid."""
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x * y % p)

## Private key functions

def secret_expand(secret: bytes) -> int:
    """Expand a 32-byte secret key to a scalar."""
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = sha256(secret)
    a = int.from_bytes(h, "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a


def secret_to_public(secret: bytes) -> bytes:
    """Convert a private key to its corresponding public key."""
    a = secret_expand(secret)
    return point_compress(point_mul(a, G))

# Compute candidate square root of x modulo p, with p = 3 (mod 4).
def sqrt4k3(x: int, p: int) -> int:
    """Compute square root mod p where p ≡ 3 (mod 4)."""
    return pow(x, (p + 1) // 4, p)

# Compute candidate square root of x modulo p, with p = 5 (mod 8).
def sqrt8k5(x: int, p: int) -> int:
    """Compute square root mod p where p ≡ 5 (mod 8)."""
    y = pow(x, (p + 3) // 8, p)
    # If the square root exists, it is either y or y*2^(p-1)/4.
    if (y * y) % p == x % p:
        return y
    else:
        z = pow(2, (p - 1) // 4, p)
        return (y * z) % p

# Decode a hexadecimal string representation of the integer.
def hexi(s: str) -> int:
    """Decode hexadecimal string to integer."""
    return int.from_bytes(bytes.fromhex(s), byteorder="big")

# Rotate a word x by b places to the left.
def rol(x: int, b: int) -> int:
    """Rotate a 64-bit word left by b bits."""
    return ((x << b) | (x >> (64 - b))) & (2**64 - 1)

# From little endian.
def from_le(s: bytes) -> int:
    """Convert little-endian bytes to integer."""
    return int.from_bytes(s, byteorder="little")

# Some low-ish level crypto specific to OpenADP.

def prefixed(a: bytes) -> bytes:
    """Return a 16-bit length prefixed (little-endian) byte string."""
    l = len(a)
    if len(a) >= 1 << 16:
        raise Exception("Input string too long")
    prefix = int.to_bytes(l, 2, "little")
    return prefix + a


def H(UID: bytes, DID: bytes, BID: bytes, pin: bytes) -> Point4D:
    """
    Hash function mapping input parameters to a valid curve point.
    
    Args:
        UID: User identifier
        DID: Device identifier  
        BID: Backup identifier
        pin: PIN value
        
    Returns:
        A valid point on the curve with correct order
    """
    s = sha256(prefixed(UID) + prefixed(DID) + prefixed(BID) + pin)
    y_base = int.from_bytes(s, "little")
    sign = y_base >> 255
    y_base &= ((1 << 255) - 1)
    counter = 0
    
    while True:
        y = y_base ^ counter
        x = recover_x(y, sign)
        if x is not None:
            # Force the point to be in a group of order q
            P = expand((x, y))
            P = point_mul8(P)
            if point_valid(P):
                return P
        counter += 1


def deriveEncKey(P: Point4D) -> bytes:
    """
    Derive an encryption key from a curve point.
    
    Args:
        P: Point in expanded format
        
    Returns:
        32-byte encryption key
    """
    p_compressed = point_compress(P)
    hkdf = HKDF(hashes.SHA256(), 32, b"", b"OpenADP enc_key derivation")
    return hkdf.derive(p_compressed)

## X25519 functions for Noise protocol

def x25519_generate_keypair() -> Tuple[bytes, bytes]:
    """Generates an X25519 keypair."""
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    return (bytes(private_key), bytes(public_key))

def x25519_public_key_from_private(private_key_bytes: bytes) -> bytes:
    """Derives the X25519 public key from a private key."""
    private_key = nacl.public.PrivateKey(private_key_bytes)
    return bytes(private_key.public_key)

def x25519_dh(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """Performs X25519 Diffie-Hellman key exchange."""
    private_key = nacl.public.PrivateKey(private_key_bytes)
    public_key = nacl.public.PublicKey(public_key_bytes)
    shared_secret = private_key.diffie_hellman(public_key)
    return shared_secret

if __name__ == '__main__':

    A = point_mul(123, G)
    B = point_mul(456, G)
    assert point_equal(point_add(A, B), point_mul(123 + 456, G))
    assert unexpand(expand((123, 456))) == (123, 456)
    assert point_equal(point_mul(modp_inv(2, q), point_mul(2, G)), G)
