/**
 * Debug module for OpenADP JavaScript SDK
 * 
 * This module provides deterministic operations for testing and debugging,
 * allowing for reproducible results across different runs and languages.
 * It implements the same debug mode functionality as the Go, Python, and C++ versions.
 */

// Global debug state
let debugMode = false;
let deterministicCounter = 0;

/**
 * Enable or disable debug mode for deterministic operations
 */
export function setDebugMode(enabled) {
    debugMode = enabled;
    deterministicCounter = 0; // Reset counter when enabling/disabling
    
    if (enabled) {
        debugLog("Debug mode enabled - all operations are now deterministic");
    } else {
        debugLog("Debug mode disabled - randomness restored");
    }
}

/**
 * Return whether debug mode is currently enabled
 */
export function isDebugModeEnabled() {
    return debugMode;
}

/**
 * Print a debug message if debug mode is enabled
 */
export function debugLog(message) {
    if (debugMode) {
        console.log(`[DEBUG] ${message}`);
    }
}

/**
 * Return a large deterministic scalar for the main secret r.
 * This is a fixed large value that properly exercises the cryptographic operations.
 * 
 * Returns the same value as Go, Python, and C++ implementations:
 * 0x023456789abcdef0fedcba987654320ffd555c99f7c5421aa6ca577e195e5e23
 */
export function getDeterministicMainSecret() {
    if (!debugMode) {
        throw new Error("getDeterministicMainSecret called outside debug mode");
    }
    
    // Use the same large deterministic constant as other implementations
    // This is the hex pattern that matches Python/Go/C++ (64 characters, even length)
    // 64 characters (even length) for consistent hex parsing across all SDKs
    const deterministicSecret = "023456789abcdef0fedcba987654320ffd555c99f7c5421aa6ca577e195e5e23";
    
    debugLog(`Using deterministic main secret r = 0x${deterministicSecret}`);
    return deterministicSecret;
}

/**
 * Return a deterministic scalar for testing.
 * In debug mode, the main secret r should always be 1
 */
export function getDeterministicRandomScalar() {
    if (!debugMode) {
        throw new Error("getDeterministicRandomScalar called outside debug mode");
    }
    
    debugLog("Using deterministic scalar r = 1");
    return 1n; // Return as BigInt
}

/**
 * Return deterministic polynomial coefficients for Shamir secret sharing.
 * These are sequential: 1, 2, 3, ... for reproducible results.
 */
export function getDeterministicPolynomialCoefficient() {
    if (!debugMode) {
        throw new Error("getDeterministicPolynomialCoefficient called outside debug mode");
    }
    
    deterministicCounter++;
    debugLog(`Using deterministic polynomial coefficient: ${deterministicCounter}`);
    return BigInt(deterministicCounter);
}

/**
 * Return deterministic hex string for testing.
 */
export function getDeterministicRandomHex(length) {
    if (!debugMode) {
        throw new Error("getDeterministicRandomHex called outside debug mode");
    }
    
    deterministicCounter++;
    
    // Generate deterministic hex string
    const hexChars = [];
    for (let i = 0; i < length; i++) {
        const value = (deterministicCounter + i) % 256;
        hexChars.push(value.toString(16).padStart(2, '0'));
    }
    
    const result = hexChars.slice(0, length).join('');
    debugLog(`Generated deterministic hex (${length} chars): ${result}`);
    return result;
}

/**
 * Return deterministic bytes for testing.
 */
export function getDeterministicRandomBytes(length) {
    if (!debugMode) {
        throw new Error("getDeterministicRandomBytes called outside debug mode");
    }
    
    deterministicCounter++;
    
    // Generate deterministic bytes
    const result = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        result[i] = (deterministicCounter + i) % 256;
    }
    
    debugLog(`Generated deterministic bytes (${length} bytes)`);
    return result;
}

/**
 * Return a fixed ephemeral secret for reproducible Noise handshakes.
 * This should be 32 bytes for X25519.
 * Uses the same ephemeral secret as Python/Go/C++ for consistency.
 */
export function getDeterministicEphemeralSecret() {
    if (!debugMode) {
        throw new Error("getDeterministicEphemeralSecret called outside debug mode");
    }
    
    debugLog("Using deterministic ephemeral secret");
    // Fixed ephemeral secret for reproducible Noise handshakes (32 bytes for X25519)
    // Use the same ephemeral secret as Python/Go/C++ implementations: 0x00...04
    // Session IDs will be different to avoid collisions, but ephemeral secrets should match
    const ephemeralSecret = new Uint8Array([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
    ]);
    
    debugLog(`Using deterministic ephemeral secret: ${Array.from(ephemeralSecret).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    return ephemeralSecret;
}

/**
 * Return a fixed base auth code for deterministic testing
 */
export function getDeterministicBaseAuthCode() {
    if (!debugMode) {
        throw new Error("getDeterministicBaseAuthCode called outside debug mode");
    }
    
    // Use the same deterministic base auth code as other implementations
    const baseAuthCode = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    debugLog(`Using deterministic base auth code: ${baseAuthCode}`);
    return baseAuthCode;
}

/**
 * Provide either deterministic or cryptographically secure random generation
 * This is the main function that should be used throughout the codebase for random number generation
 */
export function secureRandom(max) {
    if (debugMode) {
        // In debug mode, return deterministic values
        // For the main secret, always return 1
        debugLog("Using deterministic random value: 1");
        return 1n;
    }
    
    // In normal mode, use cryptographically secure random
    // This would need to be implemented with crypto.randomBytes() and proper modular arithmetic
    throw new Error("Secure random generation not implemented for production mode");
}

/**
 * Provide deterministic or secure random coefficients for Shamir secret sharing
 */
export function secureRandomCoefficient(max) {
    if (debugMode) {
        // In debug mode, return sequential deterministic coefficients
        return getDeterministicPolynomialCoefficient();
    }
    
    // In normal mode, use cryptographically secure random
    throw new Error("Secure random coefficient generation not implemented for production mode");
}

/**
 * Return either deterministic or cryptographically secure random scalar.
 * In debug mode, returns the deterministic main secret.
 * In normal mode, returns null (caller should generate secure random).
 */
export function secureRandomScalar() {
    if (debugMode) {
        return getDeterministicMainSecret();
    }
    return null;
}

/**
 * Return either deterministic or cryptographically secure random coefficient.
 * In debug mode, returns sequential deterministic coefficients.
 * In normal mode, returns null (caller should generate secure random).
 */
export function secureRandomCoefficientOrNull() {
    if (debugMode) {
        return getDeterministicPolynomialCoefficient();
    }
    return null;
} 