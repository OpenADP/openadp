/**
 * OpenADP Cryptographic Operations
 * 
 * JavaScript implementation of cryptographic primitives matching the Python/Go implementation:
 * - Ed25519 elliptic curve operations
 * - Point compression/decompression 
 * - Shamir secret sharing
 * - Hash-to-point function H
 * - HKDF key derivation
 */

import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import * as debug from './debug.js';

// Ed25519 curve parameters
export const P = BigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949'); // 2^255 - 19
export const Q = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989'); // 2^252 + 27742317777372353535851937790883648493
export const D = BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'); // -121665 * (121666^(-1)) mod P

/**
 * 2D point representation for Ed25519
 */
export class Point2D {
    constructor(x, y) {
        this.x = BigInt(x) % P;
        this.y = BigInt(y) % P;
    }

    equals(other) {
        return this.x === other.x && this.y === other.y;
    }

    toString() {
        return `Point2D(x=${this.x}, y=${this.y})`;
    }
}

/**
 * 4D point representation for Ed25519 (extended coordinates)
 */
export class Point4D {
    constructor(x, y, z, t) {
        this.x = BigInt(x) % P;
        this.y = BigInt(y) % P;
        this.z = BigInt(z) % P;
        this.t = BigInt(t) % P;
    }

    equals(other) {
        // First try the fast path - direct coordinate comparison
        if (this.x === other.x && this.y === other.y && 
            this.z === other.z && this.t === other.t) {
            return true;
        }
        
        // If that fails, use cross-multiplication (cheaper than modular inverse)
        // x1/z1 == x2/z2  <==>  x1 * z2 == x2 * z1
        const left_x = (this.x * other.z) % P;
        const right_x = (other.x * this.z) % P;
        
        if (left_x !== right_x) {
            return false;
        }
        
        // y1/z1 == y2/z2  <==>  y1 * z2 == y2 * z1
        const left_y = (this.y * other.z) % P;
        const right_y = (other.y * this.z) % P;
        
        return left_y === right_y;
    }

    toString() {
        return `Point4D(x=${this.x}, y=${this.y}, z=${this.z}, t=${this.t})`;
    }
}

// Base point G for Ed25519
export const G = new Point4D(
    BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
    BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
    BigInt('1'),
    BigInt('46827403850823179245072216630277197565144205554125654976674165829533817101731')
);

/**
 * Compute modular inverse using extended Euclidean algorithm
 */
export function modInverse(a, m) {
    a = ((a % m) + m) % m;
    
    function extendedGcd(a, b) {
        if (a === 0n) {
            return [b, 0n, 1n];
        }
        const [gcd, x1, y1] = extendedGcd(b % a, a);
        const x = y1 - (b / a) * x1;
        const y = x1;
        return [gcd, x, y];
    }
    
    const [gcd, x] = extendedGcd(BigInt(a), BigInt(m));
    if (gcd !== 1n) {
        throw new Error('Modular inverse does not exist');
    }
    return ((x % m) + m) % m;
}

/**
 * Recover x coordinate from y coordinate and sign bit
 */
function recoverX(y, sign) {
    // x^2 = (y^2 - 1) / (d*y^2 + 1)
    const y2 = (y * y) % P;
    const numerator = (y2 - 1n + P) % P;
    const denominator = (D * y2 + 1n) % P;
    
    try {
        const denomInv = modInverse(denominator, P);
        const x2 = (numerator * denomInv) % P;
        
        // Compute square root using Tonelli-Shanks
        let x = modPow(x2, (P + 3n) / 8n, P);
        
        // Check if it's actually a square root
        if ((x * x) % P !== x2) {
            x = (x * modPow(2n, (P - 1n) / 4n, P)) % P;
            if ((x * x) % P !== x2) {
                return null;
            }
        }
        
        // Adjust sign
        if ((x % 2n) !== BigInt(sign)) {
            x = P - x;
        }
        
        return x;
    } catch {
        return null;
    }
}

/**
 * Modular exponentiation
 */
function modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}

/**
 * Compress a Point4D to 32 bytes (matches Go PointCompress)
 */
export function pointCompress(point) {
    // Convert to affine coordinates
    if (point.z === 0n) {
        throw new Error('Cannot compress point at infinity');
    }
    
    const zInv = modInverse(point.z, P);
    const x = (point.x * zInv) % P;
    const y = (point.y * zInv) % P;
    
    // Encode y with sign bit of x
    const sign = x & 1n;
    const yWithSign = y | (sign << 255n);
    
    // Convert to little-endian 32 bytes
    const result = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        for (let bit = 0; bit < 8; bit++) {
            if ((yWithSign >> BigInt(i * 8 + bit)) & 1n) {
                result[i] |= (1 << bit);
            }
        }
    }
    
    return result;
}

/**
 * Decompress 32 bytes to a Point4D (matches Go PointDecompress)
 */
export function pointDecompress(data) {
    if (data.length !== 32) {
        throw new Error('Invalid input length for decompression');
    }
    
    // Convert from little-endian
    let y = 0n;
    for (let i = 0; i < 32; i++) {
        for (let bit = 0; bit < 8; bit++) {
            if ((data[i] >> bit) & 1) {
                y |= (1n << BigInt(i * 8 + bit));
            }
        }
    }
    
    const sign = Number((y >> 255n) & 1n);
    y &= (1n << 255n) - 1n; // Clear sign bit
    
    const x = recoverX(y, sign);
    if (x === null) {
        throw new Error('Invalid point');
    }
    
    // Convert to extended coordinates
    const xy = (x * y) % P;
    const point = new Point4D(x, y, 1n, xy);
    
    // Validate the point
    if (!isValidPoint(point)) {
        throw new Error('Invalid point: failed validation');
    }
    
    return point;
}

/**
 * Check if a point is valid on the Ed25519 curve
 */
export function isValidPoint(point) {
    const { x, y, z, t } = point;
    
    // Check t = xy/z
    if (z !== 0n) {
        const expectedT = (x * y * modInverse(z, P)) % P;
        if (t !== expectedT) {
            return false;
        }
    }
    
    // Check curve equation: -x^2 + y^2 = z^2 + d*t^2
    const left = ((-x * x + y * y) % P + P) % P;
    const right = (z * z + D * t * t) % P;
    return left === right;
}

/**
 * Add two points in extended coordinates
 */
export function pointAdd(p1, p2) {
    const { x: x1, y: y1, z: z1, t: t1 } = p1;
    const { x: x2, y: y2, z: z2, t: t2 } = p2;
    
    // Extended coordinates addition formula for Ed25519
    const a = ((y1 - x1 + P) % P * (y2 - x2 + P) % P) % P;
    const b = ((y1 + x1) % P * (y2 + x2) % P) % P;
    const c = (2n * D % P * t1 % P * t2 % P) % P;
    const d = (2n * z1 % P * z2 % P) % P;
    
    const e = (b - a + P) % P;
    const f = (d - c + P) % P;
    const g = (d + c) % P;
    const h = (b + a) % P;
    
    const x3 = (e * f) % P;
    const y3 = (g * h) % P;
    const t3 = (e * h) % P;
    const z3 = (f * g) % P;
    
    return new Point4D(x3, y3, z3, t3);
}

/**
 * Multiply point by scalar using double-and-add
 */
export function pointMul(scalar, point) {
    // Convert to affine coordinates for clearer debugging (like Go)
    const zInv = modInverse(point.z, P);
    const affineX = (point.x * zInv) % P;
    const affineY = (point.y * zInv) % P;
    
    if (scalar === 0n) {
        return new Point4D(0n, 1n, 1n, 0n); // Identity point
    }
    
    let result = new Point4D(0n, 1n, 1n, 0n); // Identity point
    let addend = point;
    let k = BigInt(scalar);
    
    while (k > 0n) {
        if (k & 1n) {
            result = pointAdd(result, addend);
        }
        addend = pointAdd(addend, addend); // Double
        k >>= 1n;
    }
    
    // Debug logging for result (like Go)
    const resultZinv = modInverse(result.z, P);
    const resultX = (result.x * resultZinv) % P;
    const resultY = (result.y * resultZinv) % P;
    
    return result;
}

/**
 * Multiply point by 8 (cofactor)
 */
export function pointMul8(point) {
    // Multiply by 8 = 2^3, so we double 3 times (matches Go implementation)
    let result = pointAdd(point, point);          // 2P
    result = pointAdd(result, result);            // 4P
    result = pointAdd(result, result);            // 8P
    return result;
}

/**
 * Convert Point2D to Point4D (extended coordinates)
 */
export function expand(point2d) {
    const xy = (point2d.x * point2d.y) % P;
    return new Point4D(point2d.x, point2d.y, 1n, xy);
}

/**
 * Convert Point4D to Point2D (affine coordinates)
 */
export function unexpand(point4d) {
    if (point4d.z === 0n) {
        throw new Error('Cannot convert point at infinity');
    }
    
    const zInv = modInverse(point4d.z, P);
    const x = (point4d.x * zInv) % P;
    const y = (point4d.y * zInv) % P;
    
    return new Point2D(x, y);
}

/**
 * SHA256 hash function
 */
export function sha256Hash(data) {
    return sha256(data);
}

/**
 * Add OpenADP prefix to data before hashing
 */
export function prefixed(data) {
    // Add 16-bit length prefix (little-endian) like Go implementation
    const length = data.length;
    if (length >= (1 << 16)) {
        throw new Error('Input string too long');
    }
    
    const prefix = new Uint8Array(2);
    prefix[0] = length & 0xFF;
    prefix[1] = (length >> 8) & 0xFF;
    
    const combined = new Uint8Array(prefix.length + data.length);
    combined.set(prefix);
    combined.set(data, prefix.length);
    return combined;
}

/**
 * Hash-to-point function H (matches Go implementation exactly)
 */
export function H(uid, did, bid, pin) {
    // Convert strings to bytes if needed
    const uidBytes = typeof uid === 'string' ? new TextEncoder().encode(uid) : uid;
    const didBytes = typeof did === 'string' ? new TextEncoder().encode(did) : did;
    const bidBytes = typeof bid === 'string' ? new TextEncoder().encode(bid) : bid;
    const pinBytes = pin;
    
    // Concatenate all inputs with length prefixes (like Go implementation)
    const prefixedUid = prefixed(uidBytes);
    const prefixedDid = prefixed(didBytes);
    const prefixedBid = prefixed(bidBytes);
    
    const totalLength = prefixedUid.length + prefixedDid.length + prefixedBid.length + pinBytes.length;
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    
    combined.set(prefixedUid, offset);
    offset += prefixedUid.length;
    combined.set(prefixedDid, offset);
    offset += prefixedDid.length;
    combined.set(prefixedBid, offset);
    offset += prefixedBid.length;
    combined.set(pinBytes, offset);
    
    // Hash the combined data
    const hashBytes = sha256Hash(combined);
    
    // Convert hash to big integer (little-endian like Go)
    let yBase = 0n;
    for (let i = 0; i < 32; i++) {
        for (let bit = 0; bit < 8; bit++) {
            if ((hashBytes[i] >> bit) & 1) {
                yBase |= (1n << BigInt(i * 8 + bit));
            }
        }
    }
    
    const sign = Number((yBase >> 255n) & 1n);
    yBase &= (1n << 255n) - 1n; // Clear sign bit
    
    let counter = 0;
    while (counter < 1000) { // Safety limit
        // XOR with counter to find valid point
        const y = yBase ^ BigInt(counter);
        
        const x = recoverX(y, sign);
        if (x !== null) {
            // Create point and multiply by 8 to ensure it's in the right subgroup
            const point = new Point4D(x, y, 1n, (x * y) % P);
            const result = pointMul8(point);
            if (isValidPoint(result)) {
                return result;
            }
        }
        
        counter++;
    }
    
    // Fallback to generator point G if no valid point found (matches Go implementation)
    // Ed25519 generator point in extended coordinates
    return new Point4D(
        15112221349535400772501151409588531511454012693041857206046113283949847762202n, // G.x
        46316835694926478169428394003475163141307993866256225615783033603165251855960n, // G.y  
        1n,                                                                                    // G.z
        46827403850823179245072216630277197565144205554125654976674165829533817101731n     // G.t = G.x * G.y
    );
}

/**
 * Convert a 4D point to 2D affine coordinates for consistent logging
 * This ensures that equivalent points in different coordinate systems appear identical
 */
export function point4DTo2D(point4d) {
    if (point4d.z === 0n) {
        throw new Error('Cannot convert point at infinity to 2D');
    }
    
    const zInv = modInverse(point4d.z, P);
    const x = (point4d.x * zInv) % P;
    const y = (point4d.y * zInv) % P;
    
    return new Point2D(x, y);
}

/**
 * Log a point in a consistent format (always as 2D affine coordinates)
 */
export function logPoint(label, point) {
    if (debug.isDebugModeEnabled()) {
        if (point instanceof Point4D) {
            const point2d = point4DTo2D(point);
            const xHex = point2d.x.toString(16).padStart(64, '0');
            const yHex = point2d.y.toString(16).padStart(64, '0');
            debug.debugLog(`${label} (converted from 4D): (${xHex}, ${yHex})`);
        } else if (point instanceof Point2D) {
            const xHex = point.x.toString(16).padStart(64, '0');
            const yHex = point.y.toString(16).padStart(64, '0');
            debug.debugLog(`${label}: (${xHex}, ${yHex})`);
        } else {
            debug.debugLog(`${label}: ${point.toString()}`);
        }
    }
}

/**
 * Derive encryption key from point using HKDF (matches Go DeriveEncKey)
 */
export function deriveEncKey(point) {
    const compressed = pointCompress(point);
    
    // Use HKDF with proper salt and info like Go implementation
    const salt = new TextEncoder().encode('OpenADP-EncKey-v1');
    const info = new TextEncoder().encode('AES-256-GCM');
    
    const key = hkdf(sha256, compressed, salt, info, 32);
    return key;
}



/**
 * Shamir Secret Sharing implementation (matches Go implementation)
 */
export class ShamirSecretSharing {
    static splitSecret(secret, threshold, numShares) {
        const secretBig = BigInt(secret);
        
        if (threshold > numShares) {
            throw new Error('Threshold cannot exceed number of shares');
        }
        
        // Handle edge case where threshold = 0
        if (threshold === 0) {
            // With threshold 0, any single share contains the secret
            const shares = [];
            for (let i = 0; i < numShares; i++) {
                shares.push([i + 1, Number(secretBig)]);
            }
            return shares;
        }
        
        // Generate coefficients for polynomial
        const coefficients = [secretBig]; // a0 = secret
        if (debug.isDebugModeEnabled()) {
            debug.debugLog(`Polynomial coefficient a0 (secret): ${secretBig.toString()}`);
        }
        
        for (let i = 1; i < threshold; i++) {
            let coeff;
            if (debug.isDebugModeEnabled()) {
                // Use deterministic coefficients in debug mode
                coeff = debug.getDeterministicPolynomialCoefficient();
            } else {
                // Generate random coefficient in the field (mod Q)
                const randomBytes = new Uint8Array(32);
                crypto.getRandomValues(randomBytes);
                let coeffBig = 0n;
                for (let j = 0; j < 32; j++) {
                    coeffBig = (coeffBig << 8n) | BigInt(randomBytes[j]);
                }
                // Use the proper field modulus Q
                coeff = coeffBig % Q;
            }
            coefficients.push(coeff);
        }
        
        if (debug.isDebugModeEnabled()) {
            const coeffStrs = coefficients.map(c => c.toString());
            debug.debugLog(`Polynomial coefficients: [${coeffStrs.join(', ')}]`);
        }
        
        // Evaluate polynomial at x = 1, 2, ..., numShares
        const shares = [];
        for (let x = 1; x <= numShares; x++) {
            let y = 0n;
            let xPower = 1n;
            
            for (const coeff of coefficients) {
                y = (y + coeff * xPower) % Q;
                xPower = (xPower * BigInt(x)) % Q;
            }
            
            shares.push([x, y]); // Keep y as BigInt to avoid precision loss
            
            if (debug.isDebugModeEnabled()) {
                debug.debugLog(`Share ${shares.length} (x=${x}): y=${y.toString()}`);
            }
        }
        
        // Debug summary of all shares (matching C++ format)
        if (debug.isDebugModeEnabled()) {
            debug.debugLog("📊 JAVASCRIPT SHAMIR: Generated shares summary:");
            for (let i = 0; i < shares.length; i++) {
                const [x, y] = shares[i];
                debug.debugLog(`  Share ${i + 1}: (x=${x}, y=${y.toString()})`);
            }
        }
        
        return shares;
    }
    
    static recoverSecret(shares) {
        if (shares.length === 0) {
            throw new Error('No shares provided');
        }
        
        const prime = Q;
        
        // Compute Lagrange interpolation weights w[i] (matches Go implementation exactly)
        const weights = [];
        
        for (let j = 0; j < shares.length; j++) {
            const [xj] = shares[j];
            let numerator = 1n;
            let denominator = 1n;
            
            for (let m = 0; m < shares.length; m++) {
                if (j !== m) {
                    const [xm] = shares[m];
                    // numerator = numerator * x[m] % prime (matches Go implementation)
                    numerator = (numerator * BigInt(xm)) % prime;
                    
                    // denominator = denominator * (x[m] - x[j]) % prime
                    let diff = (BigInt(xm) - BigInt(xj)) % prime;
                    denominator = (denominator * diff) % prime;
                }
            }
            
            // Ensure numerator and denominator are positive
            numerator = (numerator % prime + prime) % prime;
            denominator = (denominator % prime + prime) % prime;
            
            // w[i] = numerator * denominator^(-1) % prime
            const denominatorInv = modInverse(denominator, prime);
            const wi = (numerator * denominatorInv) % prime;
            weights[j] = (wi % prime + prime) % prime;
        }
        
        // Compute weighted sum: secret = sum(w[i] * y[i]) % prime
        let secret = 0n;
        
        for (let i = 0; i < shares.length; i++) {
            const [, yi] = shares[i];
            const term = (weights[i] * yi) % prime; // yi is already BigInt
            secret = (secret + term) % prime;
        }
        
        // Ensure result is positive and in correct range
        secret = (secret % prime + prime) % prime;
        
        // Convert to number if it fits in safe integer range
        if (secret <= BigInt(Number.MAX_SAFE_INTEGER)) {
            return Number(secret);
        } else {
            return secret;
        }
    }
}

/**
 * Point share for point-based secret sharing (matches Go PointShare)
 */
export class PointShare {
    constructor(x, point) {
        this.x = x;
        this.point = point;
    }
}

/**
 * Recover point secret from point shares (matches Go RecoverPointSecret)
 */
export function recoverPointSecret(pointShares) {
    if (pointShares.length === 0) {
        throw new Error('No point shares provided');
    }
    
    const prime = Q;
    
    // Compute Lagrange interpolation weights w[i] (same as scalar Shamir Secret Sharing)
    const weights = [];
    
    for (let j = 0; j < pointShares.length; j++) {
        const { x: xj } = pointShares[j];
        let numerator = 1n;
        let denominator = 1n;
        
        for (let m = 0; m < pointShares.length; m++) {
            if (j !== m) {
                const { x: xm } = pointShares[m];
                // numerator = numerator * x[m] % prime (matches Go implementation)
                numerator = (numerator * BigInt(xm)) % prime;
                
                // denominator = denominator * (x[m] - x[j]) % prime
                let diff = (BigInt(xm) - BigInt(xj)) % prime;
                denominator = (denominator * diff) % prime;
            }
        }
        
        // Ensure numerator and denominator are positive
        numerator = (numerator % prime + prime) % prime;
        denominator = (denominator % prime + prime) % prime;
        
        // w[i] = numerator * denominator^(-1) % prime
        const denominatorInv = modInverse(denominator, prime);
        const wi = (numerator * denominatorInv) % prime;
        weights[j] = (wi % prime + prime) % prime;
    }
    
    // Apply the Shamir recovery formula directly to points:
    // S*G = ∑(i) w_i * (s_i * G) = ∑(i) (w_i * s_i) * G
    // Since our pointShares[i].point represents s_i * G, we compute:
    // result = ∑(i) w_i * pointShares[i].point
    
    let result = new Point4D(0n, 1n, 1n, 0n); // Identity point in extended coordinates
    
    for (let j = 0; j < pointShares.length; j++) {
        // Convert point to extended coordinates and multiply by weight
        const extendedPoint = expand(pointShares[j].point);
        const weightedPoint = pointMul(weights[j], extendedPoint);
        result = pointAdd(result, weightedPoint);
    }
    
    // Convert back to affine coordinates
    return unexpand(result);
} 
