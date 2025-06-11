#!/usr/bin/env python3
"""
Shamir Secret Sharing Implementation

This module implements Shamir's secret sharing scheme as described in:
https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing

Provides functions for:
- Creating random shares from a secret
- Recovering secrets from a threshold number of shares
- Working with elliptic curve points for OpenADP
"""

import secrets
from typing import List, Tuple

import crypto

# Type definitions
Share = Tuple[int, int]  # (x, y) coordinate pair
PointShare = Tuple[int, crypto.Point2D]  # (x, point) pair


def eval_at(poly: List[int], x: int, prime: int) -> int:
    """
    Evaluate polynomial (coefficient tuple) at x.
    
    Used to generate Shamir shares in make_random_shares below.
    
    Args:
        poly: List of polynomial coefficients [a0, a1, a2, ...]
        x: X value to evaluate at
        prime: Prime modulus for arithmetic
        
    Returns:
        Polynomial value at x mod prime
    """
    x_pow = 1
    result = 0
    for coeff in poly:
        result = (result + coeff * x_pow) % prime
        x_pow = x_pow * x % prime
    return result


def make_random_shares(secret: int, minimum: int, shares: int, prime: int = crypto.q) -> List[Share]:
    """
    Generate random Shamir shares for a given secret.
    
    Args:
        secret: The secret value to be shared
        minimum: Minimum number of shares needed to recover secret (threshold)
        shares: Total number of shares to generate
        prime: Prime modulus for arithmetic (default: crypto.q)
        
    Returns:
        List of (x, y) share points
        
    Raises:
        ValueError: If minimum > shares (secret would be irrecoverable)
    """
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")
    
    # Create random polynomial with secret as constant term
    poly = [secret] + [secrets.randbelow(prime) for i in range(minimum - 1)]
    
    # Generate share points by evaluating polynomial at x = 1, 2, ..., shares
    points = [(i, eval_at(poly, i, prime)) for i in range(1, shares + 1)]
    return points


def recover_sb(shares: List[PointShare], prime: int = crypto.q) -> crypto.Point2D:
    """
    Recover s*B from threshold number of shares s[i]*B using Lagrange interpolation.
    
    The formula is:
        w[i] = product(j != i, x[j]/(x[j] - x[i]))
        s*B = sum(w[i] * s[i]*B)
    
    Args:
        shares: List of (x, point) pairs where point = s[i]*B
        prime: Prime modulus for arithmetic (default: crypto.q)
        
    Returns:
        Recovered point s*B
    """
    # Compute Lagrange interpolation weights w[i]
    weights = []
    
    for xj, _ in shares:
        numerator = 1
        denominator = 1
        
        for xm, _ in shares:
            if xj != xm:
                numerator = numerator * xm % prime
                denominator = denominator * (xm - xj) % prime
        
        wi = numerator * pow(denominator, -1, prime) % prime
        weights.append(wi)
    
    # Compute weighted sum: s*B = sum(w[i] * s[i]*B)
    sb = crypto.zero_point
    for i in range(len(shares)):
        xi, si_b = shares[i]
        # Convert point to extended coordinates, multiply by weight, and add
        sb = crypto.point_add(sb, crypto.point_mul(weights[i], crypto.expand(si_b)))
    
    return crypto.unexpand(sb)


def main():
    """
    Test/demo function for Shamir secret sharing.
    
    Creates shares, converts them to elliptic curve points, and verifies
    that recovery works correctly with different subsets of shares.
    """
    print("Testing Shamir Secret Sharing...")
    
    p = crypto.q
    secret = secrets.randbelow(p)
    threshold = 9
    num_shares = 15
    
    print(f"Original secret: {secret}")
    print(f"Threshold: {threshold}, Total shares: {num_shares}")
    
    # Create shares
    shares = make_random_shares(secret, threshold, num_shares)
    
    # Convert secret to point for verification
    s_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
    print(f"s*G = {s_point}")
    
    # Convert the y coordinate of each share into y*G (elliptic curve point)
    point_shares = []
    for i in range(len(shares)):
        x, y = shares[i]
        y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
        point_shares.append((x, y_point))
    
    # Test recovery with first 'threshold' shares
    print(f"\nTesting recovery with first {threshold} shares...")
    recovered_point1 = recover_sb(point_shares[:threshold])
    print(f"Recovered s*G = {recovered_point1}")
    
    # Test recovery with last 'threshold' shares  
    print(f"Testing recovery with last {threshold} shares...")
    recovered_point2 = recover_sb(point_shares[num_shares - threshold:])
    print(f"Recovered s*G = {recovered_point2}")
    
    # Verify both recoveries match the original
    assert recovered_point1 == recovered_point2, "Different share subsets gave different results!"
    assert s_point == recovered_point1, "Recovery failed - points don't match!"
    
    print("✅ All tests passed! Secret sharing working correctly.")


if __name__ == '__main__':
    main()
