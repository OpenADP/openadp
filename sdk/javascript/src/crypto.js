/**
 * OpenADP Cryptographic Operations
 * 
 * This module provides all cryptographic primitives used by OpenADP:
 * - Ed25519 elliptic curve operations
 * - Point compression/decompression
 * - HKDF key derivation
 * - Shamir secret sharing
 * - Authentication code generation
 */

import crypto from 'crypto';
import forge from 'node-forge';

// Ed25519 curve parameters
const P = 2n ** 255n - 19n;  // Field prime
const Q = 2n ** 252n + 27742317777372353535851937790883648493n;  // Curve order
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;  // Curve parameter

// Base point G coordinates
const GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const GY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

/**
 * Point on Ed25519 curve in extended coordinates (X, Y, Z, T)
 */
class Point4D {
    constructor(x = 0n, y = 1n, z = 1n, t = 0n) {
        this.x = BigInt(x);
        this.y = BigInt(y);
        this.z = BigInt(z);
        this.t = BigInt(t);
    }

    /**
     * Convert to affine coordinates (x, y)
     */
    toAffine() {
        if (this.z === 0n) {
            throw new Error('Point at infinity cannot be converted to affine coordinates');
        }
        const zInv = modInverse(this.z, P);
        return new Point2D(mod(this.x * zInv, P), mod(this.y * zInv, P));
    }

    /**
     * Point addition in extended coordinates
     */
    add(other) {
        const a = mod((this.y - this.x) * (other.y - other.x), P);
        const b = mod((this.y + this.x) * (other.y + other.x), P);
        const c = mod(2n * this.t * other.t * D, P);
        const d = mod(2n * this.z * other.z, P);
        const e = mod(b - a, P);
        const f = mod(d - c, P);
        const g = mod(d + c, P);
        const h = mod(b + a, P);

        return new Point4D(
            mod(e * f, P),
            mod(g * h, P),
            mod(f * g, P),
            mod(e * h, P)
        );
    }

    /**
     * Point doubling in extended coordinates
     */
    double() {
        // Use point addition with itself for consistency
        return this.add(this);
    }

    /**
     * Scalar multiplication using double-and-add
     */
    multiply(scalar) {
        let result = new Point4D(0n, 1n, 1n, 0n);  // Identity element
        let base = new Point4D(this.x, this.y, this.z, this.t);
        let k = BigInt(scalar);

        while (k > 0n) {
            if (k & 1n) {
                result = result.add(base);
            }
            base = base.double();
            k >>= 1n;
        }

        return result;
    }

    /**
     * Check if point is the identity element
     */
    isIdentity() {
        const affine = this.toAffine();
        return affine.x === 0n && affine.y === 1n;
    }

    /**
     * Check if point is valid on the curve
     */
    isValid() {
        try {
            const affine = this.toAffine();
            return affine.isValid();
        } catch {
            return false;
        }
    }
}

/**
 * Point on Ed25519 curve in affine coordinates (x, y)
 */
class Point2D {
    constructor(x = 0n, y = 1n) {
        this.x = BigInt(x);
        this.y = BigInt(y);
    }

    /**
     * Convert to extended coordinates
     */
    toExtended() {
        return new Point4D(this.x, this.y, 1n, mod(this.x * this.y, P));
    }

    /**
     * Check if point is valid on the curve: -x^2 + y^2 = 1 + d*x^2*y^2
     */
    isValid() {
        const x2 = mod(this.x * this.x, P);
        const y2 = mod(this.y * this.y, P);
        const left = mod(y2 - x2, P);
        const right = mod(1n + D * x2 * y2, P);
        return left === right;
    }

    /**
     * Compress point to 32 bytes (Ed25519 format)
     */
    compress() {
        const bytes = new Uint8Array(32);
        
        // Encode y coordinate (little-endian)
        let y = this.y;
        for (let i = 0; i < 32; i++) {
            bytes[i] = Number(y & 0xFFn);
            y >>= 8n;
        }
        
        // Set sign bit based on x coordinate parity
        if (this.x & 1n) {
            bytes[31] |= 0x80;
        }
        
        return bytes;
    }

    /**
     * Decompress point from 32 bytes (Ed25519 format)
     */
    static decompress(bytes) {
        if (bytes.length !== 32) {
            throw new Error('Invalid compressed point length');
        }
        
        // Extract sign bit
        const signBit = (bytes[31] & 0x80) !== 0;
        
        // Extract y coordinate (clear sign bit)
        const yBytes = new Uint8Array(bytes);
        yBytes[31] &= 0x7F;
        
        let y = 0n;
        for (let i = 31; i >= 0; i--) {
            y = (y << 8n) + BigInt(yBytes[i]);
        }
        
        if (y >= P) {
            throw new Error('Invalid y coordinate');
        }
        
        // Solve for x: x^2 = (y^2 - 1) / (d*y^2 + 1)
        const y2 = mod(y * y, P);
        const numerator = mod(y2 - 1n, P);
        const denominator = mod(D * y2 + 1n, P);
        const x2 = mod(numerator * modInverse(denominator, P), P);
        
        // Compute square root
        let x = modSqrt(x2, P);
        if (x === null) {
            throw new Error('Point not on curve');
        }
        
        // Adjust sign
        if ((x & 1n) !== BigInt(signBit ? 1 : 0)) {
            x = mod(-x, P);
        }
        
        const point = new Point2D(x, y);
        if (!point.isValid()) {
            throw new Error('Invalid point');
        }
        
        return point;
    }
}

// Base point G in extended coordinates
const G = new Point4D(GX, GY, 1n, mod(GX * GY, P));

/**
 * Modular arithmetic helper functions
 */
function mod(a, m) {
    const result = a % m;
    return result < 0n ? result + m : result;
}

function modInverse(a, m) {
    const [gcd, x] = extendedGcd(a, m);
    if (gcd !== 1n) {
        throw new Error('Modular inverse does not exist');
    }
    return mod(x, m);
}

function extendedGcd(a, b) {
    if (b === 0n) {
        return [a, 1n, 0n];
    }
    const [gcd, x1, y1] = extendedGcd(b, a % b);
    const x = y1;
    const y = x1 - (a / b) * y1;
    return [gcd, x, y];
}

function modSqrt(n, p) {
    // Tonelli-Shanks algorithm for computing square roots modulo p
    if (modPow(n, (p - 1n) / 2n, p) !== 1n) {
        return null; // n is not a quadratic residue
    }
    
    // Find Q and S such that p - 1 = Q * 2^S with Q odd
    let q = p - 1n;
    let s = 0n;
    while (q % 2n === 0n) {
        q /= 2n;
        s++;
    }
    
    if (s === 1n) {
        return modPow(n, (p + 1n) / 4n, p);
    }
    
    // Find a quadratic non-residue z
    let z = 2n;
    while (modPow(z, (p - 1n) / 2n, p) !== p - 1n) {
        z++;
    }
    
    let m = s;
    let c = modPow(z, q, p);
    let t = modPow(n, q, p);
    let r = modPow(n, (q + 1n) / 2n, p);
    
    while (t !== 1n) {
        // Find the smallest i such that t^(2^i) = 1
        let i = 1n;
        let temp = mod(t * t, p);
        while (temp !== 1n) {
            temp = mod(temp * temp, p);
            i++;
        }
        
        // Update values
        const b = modPow(c, modPow(2n, m - i - 1n, p - 1n), p);
        m = i;
        c = mod(b * b, p);
        t = mod(t * c, p);
        r = mod(r * b, p);
    }
    
    return r;
}

function modPow(base, exponent, modulus) {
    let result = 1n;
    base = mod(base, modulus);
    
    while (exponent > 0n) {
        if (exponent & 1n) {
            result = mod(result * base, modulus);
        }
        exponent >>= 1n;
        base = mod(base * base, modulus);
    }
    
    return result;
}

/**
 * Hash-to-point function H(data) -> Point
 * Used for deriving points from arbitrary data
 */
function hashToPoint(data) {
    const hash = crypto.createHash('sha512').update(data).digest();
    
    // Try to find a valid point by incrementing a counter
    for (let counter = 0; counter < 256; counter++) {
        const input = Buffer.concat([hash, Buffer.from([counter])]);
        const pointHash = crypto.createHash('sha512').update(input).digest();
        
        // Take first 32 bytes as y coordinate
        const yBytes = pointHash.slice(0, 32);
        yBytes[31] &= 0x7F; // Clear sign bit
        
        try {
            const point = Point2D.decompress(yBytes);
            return point;
        } catch {
            continue; // Try next counter value
        }
    }
    
    throw new Error('Failed to find valid point');
}

/**
 * HKDF key derivation function
 */
function hkdf(ikm, salt = null, info = null, length = 32) {
    // Extract phase
    const actualSalt = salt || Buffer.alloc(32, 0);
    const prk = crypto.createHmac('sha256', actualSalt).update(ikm).digest();
    
    // Expand phase
    const n = Math.ceil(length / 32);
    let okm = Buffer.alloc(0);
    let t = Buffer.alloc(0);
    
    for (let i = 1; i <= n; i++) {
        const hmac = crypto.createHmac('sha256', prk);
        hmac.update(t);
        if (info) hmac.update(info);
        hmac.update(Buffer.from([i]));
        t = hmac.digest();
        okm = Buffer.concat([okm, t]);
    }
    
    return okm.slice(0, length);
}

/**
 * Shamir Secret Sharing
 */
class ShamirSecretSharing {
    /**
     * Split secret into n shares with threshold t
     */
    static split(secret, threshold, numShares) {
        if (threshold > numShares) {
            throw new Error('Threshold cannot be greater than number of shares');
        }
        if (threshold < 1) {
            throw new Error('Threshold must be at least 1');
        }
        
        // For secrets larger than Q, we need to reduce them modulo Q
        // but preserve the original length for reconstruction
        const originalLength = secret.length;
        const secretInt = this.bytesToBigInt(secret) % Q;
        const coefficients = [secretInt];
        
        // Generate random coefficients for polynomial
        for (let i = 1; i < threshold; i++) {
            coefficients.push(this.randomBigInt(Q));
        }
        
        // Evaluate polynomial at points 1, 2, ..., numShares
        const shares = [];
        for (let x = 1; x <= numShares; x++) {
            let y = 0n;
            let xPower = 1n;
            
            for (const coeff of coefficients) {
                y = mod(y + mod(coeff * xPower, Q), Q);
                xPower = mod(xPower * BigInt(x), Q);
            }
            
            shares.push({ x: x, y: y, length: originalLength });
        }
        
        return shares;
    }
    
    /**
     * Recover secret from shares using Lagrange interpolation
     */
    static recover(shares) {
        if (shares.length === 0) {
            throw new Error('No shares provided');
        }
        
        let secret = 0n;
        
        for (let i = 0; i < shares.length; i++) {
            let numerator = 1n;
            let denominator = 1n;
            
            for (let j = 0; j < shares.length; j++) {
                if (i !== j) {
                    numerator = mod(numerator * BigInt(-shares[j].x), Q);
                    denominator = mod(denominator * BigInt(shares[i].x - shares[j].x), Q);
                }
            }
            
            const lagrangeCoeff = mod(numerator * modInverse(denominator, Q), Q);
            secret = mod(secret + mod(shares[i].y * lagrangeCoeff, Q), Q);
        }
        
        // Use the original length from the shares
        const originalLength = shares[0].length || 32;
        return this.bigIntToBytes(secret, originalLength);
    }
    
        static bytesToBigInt(bytes) {
        let result = 0n;
        for (let i = 0; i < bytes.length; i++) {
            result = (result << 8n) + BigInt(bytes[i]);
        }
        return result;
    }

    static bigIntToBytes(value, length) {
        const bytes = new Uint8Array(length);
        let v = value;
        for (let i = length - 1; i >= 0; i--) {
            bytes[i] = Number(v & 0xFFn);
            v >>= 8n;
        }
        return bytes;
    }
    
    static randomBigInt(max) {
        const bytes = crypto.randomBytes(32);
        let result = this.bytesToBigInt(bytes);
        return result % max;
    }
}

/**
 * Generate authentication codes for servers
 */
function generateAuthCodes(sharedSecret, serverIds) {
    const authCodes = {};
    
    for (const serverId of serverIds) {
        const input = Buffer.concat([
            Buffer.from(sharedSecret),
            Buffer.from(serverId, 'utf8')
        ]);
        const hash = crypto.createHash('sha256').update(input).digest();
        authCodes[serverId] = hash;
    }
    
    return authCodes;
}

/**
 * Convert password to PIN using PBKDF2
 */
function passwordToPin(password, salt, iterations = 100000) {
    const key = crypto.pbkdf2Sync(password, salt, iterations, 4, 'sha256');
    const pin = key.readUInt32BE(0) % 1000000;
    return pin.toString().padStart(6, '0');
}

export {
    Point2D,
    Point4D,
    G,
    P,
    Q,
    D,
    hashToPoint,
    hkdf,
    ShamirSecretSharing,
    generateAuthCodes,
    passwordToPin,
    mod,
    modInverse,
    modPow
}; 