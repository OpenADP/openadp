"""
Cryptographic operations for OpenADP.

This module implements the core cryptographic primitives used by OpenADP:
- Ed25519 elliptic curve operations
- Point compression/decompression 
- Shamir secret sharing
- HKDF key derivation
- Hash-to-point function H

All operations are designed to be compatible with the Go implementation.
"""

import hashlib
import secrets
from typing import Tuple, List, Optional, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from .debug import debug_log, is_debug_mode_enabled

# Ed25519 curve parameters
P = 2**255 - 19  # Field prime
Q = 2**252 + 27742317777372353535851937790883648493  # Curve order
D = -121665 * pow(121666, P-2, P) % P  # Curve parameter


class Point2D:
    """2D point representation for Ed25519."""
    
    def __init__(self, x: int, y: int):
        self.x = x % P
        self.y = y % P
    
    def __eq__(self, other: 'Point2D') -> bool:
        if not isinstance(other, Point2D):
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self) -> str:
        return f"Point2D(x={self.x}, y={self.y})"


class Point4D:
    """4D point representation for Ed25519 (extended coordinates)."""
    
    def __init__(self, x: int, y: int, z: int, t: int):
        self.x = x % P
        self.y = y % P
        self.z = z % P
        self.t = t % P
    
    def __eq__(self, other: 'Point4D') -> bool:
        if not isinstance(other, Point4D):
            return False
        return (self.x == other.x and self.y == other.y and 
                self.z == other.z and self.t == other.t)
    
    def __repr__(self) -> str:
        return f"Point4D(x={self.x}, y={self.y}, z={self.z}, t={self.t})"


# Base point G for Ed25519
G = Point4D(
    x=15112221349535400772501151409588531511454012693041857206046113283949847762202,
    y=46316835694926478169428394003475163141307993866256225615783033603165251855960,
    z=1,
    t=46827403850823179245072216630277197565144205554125654976674165829533817101731
)


def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = (a % m + m) % m
    
    # Extended Euclidean Algorithm
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m


def recover_x(y: int, sign: int) -> Optional[int]:
    """Recover x coordinate from y coordinate and sign bit."""
    # x^2 = (y^2 - 1) / (d*y^2 + 1)
    y2 = (y * y) % P
    numerator = (y2 - 1) % P
    denominator = (D * y2 + 1) % P
    
    try:
        denom_inv = mod_inverse(denominator, P)
        x2 = (numerator * denom_inv) % P
        
        # Compute square root using Tonelli-Shanks
        x = pow(x2, (P + 3) // 8, P)
        
        # Check if it's actually a square root
        if (x * x) % P != x2:
            x = (x * pow(2, (P - 1) // 4, P)) % P
            if (x * x) % P != x2:
                return None
        
        # Adjust sign
        if x % 2 != sign:
            x = P - x
            
        return x
    except ValueError:
        return None


def point_compress(point: Point4D) -> bytes:
    """Compress a Point4D to 32 bytes (matches Go PointCompress)."""
    # Convert to affine coordinates
    if point.z == 0:
        raise ValueError("Cannot compress point at infinity")
    
    z_inv = mod_inverse(point.z, P)
    x = (point.x * z_inv) % P
    y = (point.y * z_inv) % P
    
    # Encode y with sign bit of x
    sign = x & 1
    y_with_sign = y | (sign << 255)
    
    # Convert to little-endian 32 bytes
    result = bytearray(32)
    for i in range(32):
        for bit in range(8):
            if y_with_sign & (1 << (i * 8 + bit)):
                result[i] |= (1 << bit)
    
    return bytes(result)


def point_decompress(data: bytes) -> Point4D:
    """Decompress 32 bytes to a Point4D (matches Go PointDecompress)."""
    if len(data) != 32:
        raise ValueError("Invalid input length for decompression")
    
    # Convert from little-endian
    y = 0
    for i in range(32):
        for bit in range(8):
            if (data[i] >> bit) & 1:
                y |= (1 << (i * 8 + bit))
    
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1  # Clear sign bit
    
    x = recover_x(y, sign)
    if x is None:
        raise ValueError("Invalid point")
    
    # Convert to extended coordinates
    xy = (x * y) % P
    point = Point4D(x=x, y=y, z=1, t=xy)
    
    # Validate the point
    if not is_valid_point(point):
        raise ValueError("Invalid point: failed validation")
    
    return point


def is_valid_point(point: Point4D) -> bool:
    """Check if a point is valid on the Ed25519 curve."""
    # Check curve equation: -x^2 + y^2 = z^2 + d*t^2
    # In extended coordinates: -x^2 + y^2 = z^2 + d*x*y*x*y/z^2
    x, y, z, t = point.x, point.y, point.z, point.t
    
    # Check t = xy/z
    if z != 0:
        expected_t = (x * y * mod_inverse(z, P)) % P
        if t != expected_t:
            return False
    
    # Check curve equation
    left = (-x * x + y * y) % P
    right = (z * z + D * t * t) % P
    return left == right


def point_add(p1: Point4D, p2: Point4D) -> Point4D:
    """Add two points in extended coordinates."""
    x1, y1, z1, t1 = p1.x, p1.y, p1.z, p1.t
    x2, y2, z2, t2 = p2.x, p2.y, p2.z, p2.t
    
    # Extended coordinates addition formula
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    
    x3 = e * f % P
    y3 = g * h % P
    t3 = e * h % P
    z3 = f * g % P
    
    return Point4D(x3, y3, z3, t3)


def point_mul(scalar: int, point: Point4D) -> Point4D:
    """Multiply a point by a scalar using double-and-add."""
    if scalar == 0:
        return Point4D(0, 1, 1, 0)  # Identity element
    
    result = Point4D(0, 1, 1, 0)  # Identity
    addend = point
    
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)  # Double
        scalar >>= 1
    
    return result


def point_mul8(point: Point4D) -> Point4D:
    """Multiply point by 8 (matches Go pointMul8)."""
    return point_mul(8, point)


def expand(point2d: Point2D) -> Point4D:
    """Convert Point2D to Point4D (matches Go Expand)."""
    x, y = point2d.x, point2d.y
    t = (x * y) % P
    return Point4D(x, y, 1, t)


def unexpand(point4d: Point4D) -> Point2D:
    """Convert Point4D to Point2D (matches Go Unexpand)."""
    if point4d.z == 0:
        raise ValueError("Cannot unexpand point at infinity")
    
    z_inv = mod_inverse(point4d.z, P)
    x = (point4d.x * z_inv) % P
    y = (point4d.y * z_inv) % P
    return Point2D(x, y)


def sha256_hash(data: bytes) -> bytes:
    """SHA256 hash function."""
    return hashlib.sha256(data).digest()


def prefixed(data: bytes) -> bytes:
    """Add 16-bit length prefix (little-endian) to byte string."""
    length = len(data)
    if length >= (1 << 16):
        raise ValueError("Input string too long")
    
    prefix = bytes([length & 0xFF, (length >> 8) & 0xFF])
    return prefix + data


def H(uid: bytes, did: bytes, bid: bytes, pin: bytes) -> Point4D:
    """
    Hash-to-point function (matches Go H function exactly).
    
    This function deterministically maps input parameters to a point on the Ed25519 curve.
    """
    # Concatenate all inputs with length prefixes
    prefixed_uid = prefixed(uid)
    prefixed_did = prefixed(did)
    prefixed_bid = prefixed(bid)
    
    data = prefixed_uid + prefixed_did + prefixed_bid + pin
    
    # Hash and convert to point
    hash_bytes = sha256_hash(data)
    
    # Convert hash to big integer (little-endian)
    y_base = 0
    for i in range(32):
        for bit in range(8):
            if (hash_bytes[i] >> bit) & 1:
                y_base |= (1 << (i * 8 + bit))
    
    sign = (y_base >> 255) & 1
    y_base &= (1 << 255) - 1  # Clear sign bit
    
    counter = 0
    while counter < 1000:  # Safety limit
        # XOR with counter to find valid point
        y = y_base ^ counter
        
        x = recover_x(y, sign)
        if x is not None:
            # Create point and multiply by 8 to ensure it's in the right subgroup
            point = Point4D(x, y, 1, (x * y) % P)
            point = point_mul8(point)
            if is_valid_point(point):
                return point
        
        counter += 1
    
    # Fallback to base point if no valid point found
    return G


def derive_enc_key(point: Point4D) -> bytes:
    """
    Derive encryption key from point using HKDF (matches Go DeriveEncKey).
    
    Args:
        point: Point4D to derive key from
        
    Returns:
        32-byte encryption key suitable for AES-256-GCM
    """
    compressed = point_compress(point)
    
    # Use HKDF to derive 32-byte key
    salt = b"OpenADP-EncKey-v1"
    info = b"AES-256-GCM"
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(compressed)





class Ed25519:
    """Ed25519 elliptic curve operations."""
    
    @staticmethod
    def hash_to_point(uid: bytes, did: bytes, bid: bytes, pin: bytes) -> Point4D:
        """Hash inputs to a point on the curve."""
        return H(uid, did, bid, pin)
    
    @staticmethod
    def scalar_mult(scalar: int, point: Point4D) -> Point4D:
        """Multiply point by scalar."""
        return point_mul(scalar, point)
    
    @staticmethod
    def point_add(p1: Point4D, p2: Point4D) -> Point4D:
        """Add two points."""
        return point_add(p1, p2)
    
    @staticmethod
    def compress(point: Point4D) -> bytes:
        """Compress point to bytes."""
        return point_compress(point)
    
    @staticmethod
    def decompress(data: bytes) -> Point4D:
        """Decompress bytes to point."""
        return point_decompress(data)


class ShamirSecretSharing:
    """Shamir secret sharing implementation."""
    
    @staticmethod
    def split_secret(secret: int, threshold: int, num_shares: int) -> List[Tuple[int, int]]:
        """
        Split secret into shares using Shamir's scheme.
        
        Args:
            secret: Secret to split
            threshold: Minimum shares needed for recovery
            num_shares: Total number of shares to create
            
        Returns:
            List of (x, y) coordinate pairs representing shares
        """
        if threshold > num_shares:
            raise ValueError("Threshold cannot exceed number of shares")
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")
        
        debug_log(f"Splitting secret with threshold {threshold}, num_shares {num_shares}")
        
        # Generate random coefficients for polynomial
        coefficients = [secret]  # a0 = secret
        debug_log(f"Polynomial coefficient a0 (secret): {secret}")
        
        for i in range(1, threshold):
            if is_debug_mode_enabled():
                # Use deterministic coefficients in debug mode
                coeff = i
                debug_log(f"Using deterministic polynomial coefficient a{i+1}: {coeff}")
            else:
                coeff = secrets.randbelow(Q)
            coefficients.append(coeff)
        
        debug_log(f"Polynomial coefficients: {coefficients}")
        
        # Evaluate polynomial at x = 1, 2, ..., num_shares
        shares = []
        for x in range(1, num_shares + 1):
            y = 0
            x_power = 1
            for j, coeff in enumerate(coefficients):
                y = (y + coeff * x_power) % Q
                x_power = (x_power * x) % Q
            shares.append((x, y))
            debug_log(f"Share {x}: (x={x}, y={y})")
        
        debug_log(f"Generated {len(shares)} shares")
        return shares
    
    @staticmethod
    def recover_secret(shares: List[Tuple[int, int]]) -> int:
        """
        Recover secret from shares using Lagrange interpolation.
        
        Args:
            shares: List of (x, y) coordinate pairs
            
        Returns:
            Recovered secret
        """
        if len(shares) < 1:
            raise ValueError("Need at least one share")
        
        if is_debug_mode_enabled():
            debug_log("📊 PYTHON SHAMIR RECOVERY: Starting secret recovery")
            debug_log(f"   Number of shares: {len(shares)}")
            debug_log("   Input shares:")
            for i, (x, y) in enumerate(shares):
                debug_log(f"     Share {i + 1}: (x={x}, y={y})")
                debug_log(f"     Share {i + 1} y hex: {y:064x}")
            debug_log(f"   Using prime modulus Q: {Q:064x}")
            debug_log("   Starting Lagrange interpolation...")
        
        # Lagrange interpolation to find f(0)
        secret = 0
        
        for i, (xi, yi) in enumerate(shares):
            if is_debug_mode_enabled():
                debug_log(f"   Processing share {i + 1} (x={xi}, y={yi})")
            
            # Compute Lagrange basis polynomial Li(0)
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    old_numerator = numerator
                    old_denominator = denominator
                    
                    numerator = (numerator * (-xj)) % Q
                    denominator = (denominator * (xi - xj)) % Q
                    
                    if is_debug_mode_enabled():
                        debug_log(f"     Multiplying numerator by (-{xj}) = {(-xj) % Q:x}")
                        debug_log(f"     Multiplying denominator by ({xi} - {xj}) = {(xi - xj) % Q:x}")
            
            if is_debug_mode_enabled():
                debug_log(f"     Final numerator: {numerator:064x}")
                debug_log(f"     Final denominator: {denominator:064x}")
            
            # Compute Li(0) = numerator / denominator
            li_0 = (numerator * mod_inverse(denominator, Q)) % Q
            
            if is_debug_mode_enabled():
                debug_log(f"     Lagrange basis polynomial L{i}(0): {li_0:064x}")
            
            # Add yi * Li(0) to result
            term = (yi * li_0) % Q
            secret = (secret + term) % Q
            
            if is_debug_mode_enabled():
                debug_log(f"     Term {i}: y{i} * L{i}(0) = {term:064x}")
                debug_log(f"     Running total: {secret:064x}")
        
        if is_debug_mode_enabled():
            debug_log("📊 PYTHON SHAMIR RECOVERY: Completed secret recovery")
            debug_log(f"   Final recovered secret: {secret}")
            debug_log(f"   Final recovered secret hex: {secret:064x}")
        
        return secret


class PointShare:
    """Represents a point share for point-based secret recovery."""
    
    def __init__(self, x: int, point: Point2D):
        self.x = x
        self.point = point
    
    def __repr__(self) -> str:
        return f"PointShare(x={self.x}, point={self.point})"


def recover_point_secret(point_shares: List[PointShare]) -> Point2D:
    """
    Recover point secret using Lagrange interpolation on points.
    
    This implements point-based recovery where each share is (x, si*B) 
    and we want to recover s*B using Lagrange interpolation.
    """
    if len(point_shares) < 1:
        raise ValueError("Need at least one point share")
    
    # Initialize result as point at infinity (identity)
    result = Point4D(0, 1, 1, 0)
    
    for i, share_i in enumerate(point_shares):
        # Compute Lagrange coefficient Li(0)
        numerator = 1
        denominator = 1
        
        for j, share_j in enumerate(point_shares):
            if i != j:
                numerator = (numerator * (-share_j.x)) % Q
                denominator = (denominator * (share_i.x - share_j.x)) % Q
        
        # Compute Li(0) = numerator / denominator
        li_0 = (numerator * mod_inverse(denominator, Q)) % Q
        
        # Add Li(0) * (si * B) to result
        expanded_point = expand(share_i.point)
        term = point_mul(li_0, expanded_point)
        result = point_add(result, term)
    
    return unexpand(result) 
