/**
 * Key generation and recovery for OpenADP
 * 
 * This module provides high-level functions for generating encryption keys using
 * the OpenADP distributed secret sharing system, matching the Python implementation exactly.
 * 
 * This module handles the complete workflow:
 * 1. Generate random secrets and split into shares
 * 2. Register shares with distributed servers
 * 3. Recover secrets from servers during decryption
 * 4. Derive encryption keys using cryptographic functions
 */

import crypto from 'crypto';
import { Buffer } from 'buffer';
import os from 'os';
import path from 'path';
import {
    H, deriveSecret, deriveEncKey, pointMul, pointCompress, pointDecompress,
    ShamirSecretSharing, recoverPointSecret, PointShare, Point2D, Point4D,
    expand, unexpand, Q, modInverse, sha256Hash
} from './crypto.js';
import { OpenADPClient, EncryptedOpenADPClient, ServerInfo } from './client.js';

/**
 * Authentication codes for OpenADP servers
 */
export class AuthCodes {
    constructor(baseAuthCode, serverAuthCodes, userId) {
        this.baseAuthCode = baseAuthCode;
        this.serverAuthCodes = serverAuthCodes;
        this.userId = userId;
    }
}

/**
 * Result of encryption key generation
 */
export class GenerateEncryptionKeyResult {
    constructor(encryptionKey = null, error = null, serverUrls = null, threshold = null, authCodes = null) {
        this.encryptionKey = encryptionKey;
        this.error = error;
        this.serverUrls = serverUrls;
        this.threshold = threshold;
        this.authCodes = authCodes;
    }
}

/**
 * Result of encryption key recovery
 */
export class RecoverEncryptionKeyResult {
    constructor(encryptionKey = null, error = null) {
        this.encryptionKey = encryptionKey;
        this.error = error;
    }
}

/**
 * Derive UID, DID, and BID for OpenADP operations (matches Python DeriveIdentifiers)
 */
export function deriveIdentifiers(filename, userId, hostname = "") {
    // Auto-detect hostname if not provided
    if (!hostname) {
        try {
            hostname = os.hostname();
        } catch {
            hostname = "unknown";
        }
    }
    
    // Use authenticated user ID (UUID) as UID directly
    const uid = userId; // This is now the authenticated user ID (UUID)
    const did = hostname; // Device identifier
    const bid = `file://${path.basename(filename)}`; // Backup identifier for this file
    
    return [uid, did, bid];
}

/**
 * Convert user password to PIN bytes for cryptographic operations (matches Python PasswordToPin)
 */
export function passwordToPin(password) {
    // Hash password to get consistent bytes, then take first 2 bytes as PIN
    const hashBytes = sha256Hash(new TextEncoder().encode(password));
    return hashBytes.slice(0, 2); // Use first 2 bytes as PIN
}

/**
 * Generate authentication codes for OpenADP servers (matches Python GenerateAuthCodes)
 * @param {string[]} serverUrls - List of server URLs
 * @param {string} [fixedSeed] - Optional fixed seed for testing (DO NOT use in production)
 */
export function generateAuthCodes(serverUrls, fixedSeed = null) {
    let baseAuthCode;
    
    if (fixedSeed !== null) {
        // FOR TESTING ONLY - Generate deterministic auth code from seed
        const seedBytes = sha256Hash(new TextEncoder().encode(fixedSeed));
        baseAuthCode = Buffer.from(seedBytes).toString('hex');
    } else {
        // PRODUCTION - Generate random base authentication code (32 bytes = 256 bits)
        const baseAuthBytes = crypto.randomBytes(32);
        baseAuthCode = baseAuthBytes.toString('hex');
    }
    
    // Derive server-specific auth codes
    const serverAuthCodes = {};
    for (const serverUrl of serverUrls) {
        // Combine base auth code with server URL and hash (matches Python format with colon separator)
        const combined = `${baseAuthCode}:${serverUrl}`;
        const serverHash = sha256Hash(new TextEncoder().encode(combined));
        serverAuthCodes[serverUrl] = Buffer.from(serverHash).toString('hex');
    }
    
    return new AuthCodes(baseAuthCode, serverAuthCodes, "");
}

/**
 * Generate an encryption key using OpenADP distributed secret sharing (matches Python GenerateEncryptionKey)
 */
export async function generateEncryptionKey(
    filename,
    password,
    userId,
    maxGuesses = 10,
    expiration = 0,
    serverInfos = null
) {
    // Input validation
    if (!filename) {
        return new GenerateEncryptionKeyResult(null, "Filename cannot be empty");
    }
    
    if (!userId) {
        return new GenerateEncryptionKeyResult(null, "User ID cannot be empty");
    }
    
    if (maxGuesses < 0) {
        return new GenerateEncryptionKeyResult(null, "Max guesses cannot be negative");
    }
    
    try {
        // Step 1: Derive identifiers using authenticated user_id
        const [uid, did, bid] = deriveIdentifiers(filename, userId, "");
        console.log(`OpenADP: UID=${uid}, DID=${did}, BID=${bid}`);
        
        // Step 2: Convert password to PIN
        const pin = passwordToPin(password);
        
        // Step 3: Check if we have servers
        if (!serverInfos || serverInfos.length === 0) {
            return new GenerateEncryptionKeyResult(null, "No OpenADP servers available");
        }
        
        // Step 4: Initialize encrypted clients for each server by fetching their public keys
        const clients = [];
        const liveServerUrls = [];
        
        for (const serverInfo of serverInfos) {
            try {
                // Create a basic client to fetch server info first
                const basicClient = new OpenADPClient(serverInfo.url);
                
                // Fetch server info to get the public key
                const serverInfoResponse = await basicClient.getServerInfoStandardized();
                
                let publicKey = null;
                if (serverInfoResponse.noiseNkPublicKey) {
                    try {
                        publicKey = new Uint8Array(Buffer.from(serverInfoResponse.noiseNkPublicKey, 'base64'));
                    } catch (error) {
                        console.warn(`Invalid public key from server ${serverInfo.url}: ${error.message}`);
                        publicKey = null;
                    }
                }
                
                // Create encrypted client with the fetched public key
                const client = new EncryptedOpenADPClient(serverInfo.url, publicKey);
                await client.ping();
                
                clients.push(client);
                liveServerUrls.push(serverInfo.url);
                
                if (publicKey) {
                    console.log(`OpenADP: Server ${serverInfo.url} - Using Noise-NK encryption`);
                } else {
                    console.log(`OpenADP: Server ${serverInfo.url} - No encryption (no public key)`);
                }
            } catch (error) {
                console.warn(`Server ${serverInfo.url} is not accessible: ${error.message}`);
            }
        }
        
        if (clients.length === 0) {
            return new GenerateEncryptionKeyResult(null, "No live servers available");
        }
        
        console.log(`OpenADP: Using ${clients.length} live servers`);
        
        // Step 5: Generate authentication codes for live servers
        const authCodes = generateAuthCodes(liveServerUrls);
        authCodes.userId = userId;
        
        // Step 6: Calculate threshold - require majority of servers
        const threshold = Math.floor(clients.length / 2) + 1;
        console.log(`OpenADP: Using threshold ${threshold}/${clients.length} servers`);
        
        // Step 7: Generate random secret for this encryption operation
        const secret = deriveSecret(uid, did, bid, pin);
        console.log(`OpenADP: Generated secret for encryption key derivation`);
        
        // Step 8: Split secret into shares using Shamir secret sharing
        const shares = ShamirSecretSharing.splitSecret(secret, threshold, clients.length);
        console.log(`OpenADP: Split secret into ${shares.length} shares (threshold: ${threshold})`);
        
        // Step 9: Compute point H(uid, did, bid, pin) for point-based shares
        const hPoint = H(uid, did, bid, pin); // U = H(uid, did, bid, pin)
        
        // Step 9.5: Compute S = secret * U (this is the point used for key derivation, like Go)
        const sPoint = pointMul(secret, hPoint); // S = secret * U
        
        const hCompressed = pointCompress(hPoint);
        const hBase64 = Buffer.from(hCompressed).toString('base64');
        
        // Step 10: Register shares with servers
        const version = 1;
        if (expiration === 0) {
            // Set default expiration to 1 year from now
            expiration = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60);
        }
        
        console.log(`OpenADP: Registering shares with ${clients.length} servers...`);
        
        // Debug: Compute si*U values that will be sent to servers
        for (let i = 0; i < clients.length; i++) {
            const [x, y] = shares[i];
            const si = y; // The Shamir share value
            const siU = pointMul(si, hPoint); // si * U point (U = H(uid,did,bid,pin))
            const siUAffine = unexpand(siU);
            console.log(`🔍 Server ${i+1}: si=${si}`);
            console.log(`🔍 Server ${i+1}: si*U = Point(x=${siUAffine.x}, y=${siUAffine.y})`);
            
            // Convert to compressed format to match what server will compute
            const siUCompressed = pointCompress(siU);
            console.log(`🔍 Server ${i+1}: si*U compressed (hex): ${Buffer.from(siUCompressed).toString('hex')}`);
        }
        
        const registrationPromises = [];
        
        for (let i = 0; i < clients.length; i++) {
            const client = clients[i];
            const serverUrl = liveServerUrls[i];
            const [x, y] = shares[i];
            const authCode = authCodes.serverAuthCodes[serverUrl];
            
            // Convert Y coordinate to decimal string format (matches Python/Go implementations)
            // Y is the Shamir share Y coordinate, not an elliptic curve point
            // Send as decimal string to match server expectations (no scientific notation)
            const yString = y.toString(); // y is already BigInt
            
            // Debug: Show what we're sending
            const yBig = y; // y is already BigInt
            
            // Convert BigInt to hex string properly (big-endian)
            let yHex = yBig.toString(16).padStart(64, '0'); // 32 bytes = 64 hex chars
            
            console.log(`🔍 JS DEBUG: Sending Y for server ${i+1}: decimal="${yString}" hex="${yHex}"`);
            console.log(`🔍 JS DEBUG: Share ${i+1}: x=${x}, y=${y}`);
            
            const promise = client.registerSecret(
                authCode, uid, did, bid, version, x, yString, maxGuesses, expiration, true
            );
            registrationPromises.push(promise);
        }
        
        // Wait for all registrations to complete
        const registrationResults = await Promise.allSettled(registrationPromises);
        
        let successCount = 0;
        for (let i = 0; i < registrationResults.length; i++) {
            const result = registrationResults[i];
            if (result.status === 'fulfilled' && result.value === true) {
                successCount++;
                console.log(`OpenADP: ✓ Registered share with server ${liveServerUrls[i]}`);
            } else {
                console.warn(`OpenADP: ✗ Failed to register share with server ${liveServerUrls[i]}: ${result.reason?.message || 'Unknown error'}`);
            }
        }
        
        if (successCount < threshold) {
            return new GenerateEncryptionKeyResult(
                null, 
                `Failed to register enough shares. Got ${successCount}/${clients.length}, need ${threshold}`,
                liveServerUrls,
                threshold,
                authCodes
            );
        }
        
        console.log(`OpenADP: Successfully registered ${successCount}/${clients.length} shares`);
        
        // Step 11: Generate encryption key from S = secret * U (like Go)
        const sPointCompressed = pointCompress(sPoint);
        console.log(`🔍 JS ENCRYPTION DEBUG: sPoint (secret*U) compressed (hex): ${Buffer.from(sPointCompressed).toString('hex')}`);
        const encryptionKey = deriveEncKey(sPoint);
        console.log(`OpenADP: Generated 32-byte encryption key from S = secret * U`);
        
        return new GenerateEncryptionKeyResult(
            encryptionKey,
            null,
            liveServerUrls,
            threshold,
            authCodes
        );
        
    } catch (error) {
        console.error(`OpenADP encryption key generation failed: ${error.message}`);
        return new GenerateEncryptionKeyResult(null, `Key generation failed: ${error.message}`);
    }
}

/**
 * Recover an encryption key using OpenADP distributed secret sharing (matches Python RecoverEncryptionKey)
 */
export async function recoverEncryptionKey(
    filename,
    password,
    userId,
    serverInfos,
    threshold,
    authCodes
) {
    // Input validation
    if (!filename) {
        return new RecoverEncryptionKeyResult(null, "Filename cannot be empty");
    }
    
    if (!userId) {
        return new RecoverEncryptionKeyResult(null, "User ID cannot be empty");
    }
    
    if (!serverInfos || serverInfos.length === 0) {
        return new RecoverEncryptionKeyResult(null, "No OpenADP servers available");
    }
    
    if (!authCodes) {
        return new RecoverEncryptionKeyResult(null, "Authentication codes required");
    }
    
    try {
        // Step 1: Derive identifiers (same as during generation)
        const [uid, did, bid] = deriveIdentifiers(filename, userId, "");
        console.log(`OpenADP: Recovery - UID=${uid}, DID=${did}, BID=${bid}`);
        
        // Step 2: Convert password to PIN
        const pin = passwordToPin(password);
        
        // Step 3: Initialize encrypted clients
        const clients = [];
        const liveServerUrls = [];
        
        for (const serverInfo of serverInfos) {
            let publicKey = null;
            
            if (serverInfo.publicKey) {
                try {
                    if (serverInfo.publicKey.startsWith("ed25519:")) {
                        const keyB64 = serverInfo.publicKey.substring(8);
                        publicKey = new Uint8Array(Buffer.from(keyB64, 'base64'));
                    } else {
                        publicKey = new Uint8Array(Buffer.from(serverInfo.publicKey, 'base64'));
                    }
                } catch (error) {
                    console.warn(`Invalid public key for server ${serverInfo.url}: ${error.message}`);
                    publicKey = null;
                }
            }
            
            const client = new EncryptedOpenADPClient(serverInfo.url, publicKey);
            try {
                await client.ping();
                clients.push(client);
                liveServerUrls.push(serverInfo.url);
            } catch (error) {
                console.warn(`Server ${serverInfo.url} is not accessible: ${error.message}`);
            }
        }
        
        if (clients.length < threshold) {
            return new RecoverEncryptionKeyResult(
                null, 
                `Not enough live servers. Have ${clients.length}, need ${threshold}`
            );
        }
        
        console.log(`OpenADP: Recovery using ${clients.length} live servers (threshold: ${threshold})`);
        
        // Step 4: Create cryptographic context (same as encryption)
        const uPoint = H(uid, did, bid, pin);
        
        // Debug: Show the U point that we're using for recovery (convert to affine)
        const uPointAffine = unexpand(uPoint);
        console.log(`🔍 JS DECRYPTION DEBUG: U point (H(uid,did,bid,pin)) affine = Point(x=${uPointAffine.x}, y=${uPointAffine.y})`);
        
        // Generate random r for blinding (0 < r < Q)
        const randomBytes = new Uint8Array(32);
        crypto.getRandomValues(randomBytes);
        let r = 0n;
        for (let i = 0; i < 32; i++) {
            r = (r << 8n) | BigInt(randomBytes[i]);
        }
        r = r % Q;
        if (r === 0n) {
            r = 1n; // Ensure r is not zero
        }
        
        // Compute r^-1 mod q
        const rInv = modInverse(r, Q);
        
        const bPoint = pointMul(r, uPoint);
        const bPointAffine = unexpand(bPoint);
        const bCompressed = pointCompress(bPoint);
        const bBase64 = Buffer.from(bCompressed).toString('base64');
        
        console.log(`🔍 JS DECRYPTION DEBUG: Generated r = ${r}`);
        console.log(`🔍 JS DECRYPTION DEBUG: Generated B point: x=${bPointAffine.x}, y=${bPointAffine.y}`);
        console.log(`🔍 JS DECRYPTION DEBUG: B compressed (hex): ${Buffer.from(bCompressed).toString('hex')}`);
        console.log(`🔍 JS DECRYPTION DEBUG: B base64 sent to servers: ${bBase64}`);
        
        // Debug: We'll verify si*B values after we get them from servers
        console.log(`🔍 JS DECRYPTION DEBUG: Will verify si*B = r*(si*U) after receiving server responses`);
        console.log(`🔍 JS DECRYPTION DEBUG: r = ${r}`);
        

        
        // Step 5: Recover shares from servers
        console.log(`OpenADP: Recovering shares from servers...`);
        const recoveryPromises = [];
        
        for (let i = 0; i < Math.min(clients.length, threshold + 2); i++) { // Get a few extra shares for redundancy
            const client = clients[i];
            const serverUrl = liveServerUrls[i];
            const authCode = authCodes.serverAuthCodes[serverUrl];
            
            if (!authCode) {
                console.warn(`No auth code for server ${serverUrl}`);
                continue;
            }
            
            const promise = client.recoverSecret(
                authCode, uid, did, bid, bBase64, 0, true
            );
            recoveryPromises.push(promise.then(result => ({ serverUrl, result })).catch(error => ({ serverUrl, error })));
        }
        
        const recoveryResults = await Promise.allSettled(recoveryPromises);
        
        // Process recovery results
        const validShares = [];
        for (const settledResult of recoveryResults) {
            if (settledResult.status === 'fulfilled') {
                const { serverUrl, result, error } = settledResult.value;
                if (error) {
                    console.warn(`OpenADP: Failed to recover from ${serverUrl}: ${error.message}`);
                } else {
                    console.log(`OpenADP: ✓ Recovered share from ${serverUrl}`);
                    console.log(`🔍 JS DECRYPTION DEBUG: Server returned si_b (base64): ${result.si_b}`);
                    console.log(`🔍 JS DECRYPTION DEBUG: Server returned x: ${result.x}`);
                    
                    // Convert si_b back to point and then to share
                    try {
                        const siBBytes = Buffer.from(result.si_b, 'base64');
                        console.log(`🔍 JS DECRYPTION DEBUG: si_b bytes (hex): ${Buffer.from(siBBytes).toString('hex')}`);
                        
                        const siBPoint = pointDecompress(siBBytes);
                        const siBPoint2D = new Point2D(siBPoint.x, siBPoint.y);
                        
                        console.log(`🔍 JS DECRYPTION DEBUG: Decompressed si*B point: x=${siBPoint2D.x}, y=${siBPoint2D.y}`);
                        
                        // Compute rInv * siB to compare with siU from encryption
                        const siB4D = expand(siBPoint2D);
                        const computedSiU = pointMul(rInv, siB4D);
                        const computedSiUAffine = unexpand(computedSiU);
                        console.log(`🔍 JS DECRYPTION DEBUG: rInv * si*B = Point(x=${computedSiUAffine.x}, y=${computedSiUAffine.y}) (should match si*U from encryption)`);
                        
                        validShares.push(new PointShare(result.x, siBPoint2D));
                    } catch (shareError) {
                        console.warn(`Failed to process share from ${serverUrl}: ${shareError.message}`);
                    }
                }
            }
        }
        
        if (validShares.length < threshold) {
            return new RecoverEncryptionKeyResult(
                null,
                `Not enough valid shares recovered. Got ${validShares.length}, need ${threshold}`
            );
        }
        
        console.log(`OpenADP: Recovered ${validShares.length} valid shares`);
        
        // Step 6: Reconstruct secret using point-based recovery (like Go recover_sb)
        console.log(`OpenADP: Reconstructing secret from ${validShares.length} point shares...`);
        
        // Use point-based Lagrange interpolation to recover s*B (like Go RecoverPointSecret)
        // Use ALL available shares, not just threshold (matches Go implementation)
        const recoveredSB = recoverPointSecret(validShares);
        console.log(`🔍 JS DECRYPTION DEBUG: Recovered s*B from Lagrange interpolation: x=${recoveredSB.x}, y=${recoveredSB.y}`);
        
        // Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
        // This matches Go: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
        const recoveredSB4D = expand(recoveredSB);
        const originalSU = pointMul(rInv, recoveredSB4D);
        console.log(`🔍 JS DECRYPTION DEBUG: Recovered s*U after r^-1 multiplication: x=${originalSU.x}, y=${originalSU.y}`);
        
        // Debug: Also compute individual si*U values for comparison with encryption
        console.log(`🔍 JS DECRYPTION DEBUG: Computing individual si*U values from si*B shares:`);
        for (let i = 0; i < validShares.length; i++) {
            const share = validShares[i];
            const siBPoint = share.point;
            
            // Convert si*B to si*U by multiplying by r^-1
            const siB4D = expand(siBPoint);
            const siU4D = pointMul(rInv, siB4D);
            const siU2D = new Point2D(siU4D.x, siU4D.y);
            
            console.log(`🔍 Server ${i+1}: si*U recovered = Point(x=${siU2D.x}, y=${siU2D.y})`);
        }
        
        // Step 7: Derive same encryption key
        const originalSUAffine = unexpand(originalSU);
        console.log(`🔍 JS DECRYPTION DEBUG: originalSU affine = Point(x=${originalSUAffine.x}, y=${originalSUAffine.y})`);
        const originalSUCompressed = pointCompress(originalSU);
        console.log(`🔍 JS DECRYPTION DEBUG: originalSU compressed (hex): ${Buffer.from(originalSUCompressed).toString('hex')}`);
        const encryptionKey = deriveEncKey(originalSU);
        console.log(`OpenADP: Successfully recovered encryption key`);
        
        return new RecoverEncryptionKeyResult(encryptionKey, null);
        
    } catch (error) {
        console.error(`OpenADP encryption key recovery failed: ${error.message}`);
        return new RecoverEncryptionKeyResult(null, `Key recovery failed: ${error.message}`);
    }
} 
