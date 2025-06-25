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
    H, deriveEncKey, pointMul, pointCompress, pointDecompress,
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
 * Identity represents the primary key tuple for secret shares stored on servers
 */
export class Identity {
    constructor(uid, did, bid) {
        this.uid = uid;  // User ID - uniquely identifies the user
        this.did = did;  // Device ID - identifies the device/application  
        this.bid = bid;  // Backup ID - identifies the specific backup
    }
    
    toString() {
        return `UID=${this.uid}, DID=${this.did}, BID=${this.bid}`;
    }
}

/**
 * Result of encryption key generation
 */
export class GenerateEncryptionKeyResult {
    constructor(encryptionKey = null, error = null, serverInfos = null, threshold = null, authCodes = null) {
        this.encryptionKey = encryptionKey;
        this.error = error;
        this.serverInfos = serverInfos;
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
    // Generate base authentication code (32 random bytes as hex)
    let baseAuthCode;
    if (fixedSeed) {
        // For testing: use a fixed seed to generate deterministic auth codes
        const seedHash = sha256Hash(Buffer.from(fixedSeed, 'utf8'));
        baseAuthCode = Buffer.from(seedHash).toString('hex');
    } else {
        // Production: use cryptographically secure random bytes
        const randomBytes = new Uint8Array(32);
        crypto.getRandomValues(randomBytes);
        baseAuthCode = Buffer.from(randomBytes).toString('hex');
    }
    
    
    
    // Generate server-specific authentication codes
    const serverAuthCodes = {};
    for (const serverUrl of serverUrls) {
        // Derive server-specific code using SHA256 (same as Go/Python implementation)
        const combined = `${baseAuthCode}:${serverUrl}`;
        const hashBytes = sha256Hash(Buffer.from(combined, 'utf8'));
        const serverCode = Buffer.from(hashBytes).toString('hex');
        serverAuthCodes[serverUrl] = serverCode;
    }
    
    // Return with placeholder user_id (will be set by caller)
    return new AuthCodes(baseAuthCode, serverAuthCodes, "");
}

/**
 * Generate an encryption key using OpenADP distributed secret sharing
 */
export async function generateEncryptionKey(
    identity,
    password,
    maxGuesses = 10,
    expiration = 0,
    serverInfos = null
) {
    // Input validation
    if (!identity) {
        return new GenerateEncryptionKeyResult(null, "Identity cannot be null");
    }
    
    if (!identity.uid) {
        return new GenerateEncryptionKeyResult(null, "UID cannot be empty");
    }
    
    if (!identity.did) {
        return new GenerateEncryptionKeyResult(null, "DID cannot be empty");
    }
    
    if (!identity.bid) {
        return new GenerateEncryptionKeyResult(null, "BID cannot be empty");
    }
    
    if (maxGuesses < 0) {
        return new GenerateEncryptionKeyResult(null, "Max guesses cannot be negative");
    }

    console.log(`OpenADP: Identity=${identity.toString()}`);

    try {
        // Step 1: Convert password to PIN
        const pin = passwordToPin(password);
        
        // Step 2: Check if we have servers
        if (!serverInfos || serverInfos.length === 0) {
            return new GenerateEncryptionKeyResult(null, "No OpenADP servers available");
        }
        
        // Step 3: Initialize encrypted clients for each server by fetching their public keys
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
        
        // Step 4: Generate authentication codes for live servers
        const authCodes = generateAuthCodes(liveServerUrls);
        authCodes.userId = identity.uid;
        
        // Step 5: Calculate threshold - require majority of servers
        const threshold = Math.floor(clients.length / 2) + 1;
        console.log(`OpenADP: Using threshold ${threshold}/${clients.length} servers`);
        
        // Step 6: Generate RANDOM secret for this encryption operation
        // SECURITY FIX: Use random secret for Shamir secret sharing, not deterministic
        let secret = BigInt(0);
        // Generate random secret from 0 to Q-1
        // Note: secret can be 0 - this is valid for Shamir secret sharing
        const randomBytes = new Uint8Array(32);
        crypto.getRandomValues(randomBytes);
        let secretBig = BigInt(0);
        for (let i = 0; i < randomBytes.length; i++) {
            secretBig = (secretBig << BigInt(8)) | BigInt(randomBytes[i]);
        }
        secret = secretBig % Q;
        console.log(`OpenADP: Generated random secret for encryption key derivation`);
        
        // Step 7: Split secret into shares using Shamir secret sharing
        const shares = ShamirSecretSharing.splitSecret(secret, threshold, clients.length);
        console.log(`OpenADP: Split secret into ${shares.length} shares (threshold: ${threshold})`);
        
        // Step 8: Compute point H(uid, did, bid, pin) for point-based shares
        const hPoint = H(identity.uid, identity.did, identity.bid, pin); // U = H(uid, did, bid, pin)
        
        // Step 9.5: Compute S = secret * U (this is the point used for key derivation, like Go)
        const sPoint = pointMul(secret, hPoint); // S = secret * U
        
        const hCompressed = pointCompress(hPoint);
        const hBase64 = Buffer.from(hCompressed).toString('base64');
        
        // Step 10: Register shares with servers (encrypted communication)
        console.log(`OpenADP: Registering ${shares.length} shares with servers (threshold: ${threshold})...`);
        
        const version = 1;
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
            

            
            const promise = client.registerSecret(
                authCode, identity.uid, identity.did, identity.bid, version, x, yString, maxGuesses, expiration, true
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
        
        // Create ServerInfo objects for the live servers (used in both success and error cases)
        const liveServerInfos = liveServerUrls.map(url => {
            const originalServerInfo = serverInfos.find(si => si.url === url);
            return originalServerInfo || { url: url, publicKey: "", name: "Unknown" };
        });
        
        if (successCount < threshold) {
            return new GenerateEncryptionKeyResult(
                null, 
                `Failed to register enough shares. Got ${successCount}/${clients.length}, need ${threshold}`,
                liveServerInfos,
                threshold,
                authCodes
            );
        }
        
        console.log(`OpenADP: Successfully registered ${successCount}/${clients.length} shares`);
        
        // Step 11: Generate encryption key from S = secret * U (like Go)
        const sPointCompressed = pointCompress(sPoint);
        const encryptionKey = deriveEncKey(sPoint);
        console.log(`OpenADP: Generated 32-byte encryption key from S = secret * U`);
        
        return new GenerateEncryptionKeyResult(
            encryptionKey,
            null,
            liveServerInfos,
            threshold,
            authCodes
        );
        
    } catch (error) {
        console.error(`OpenADP encryption key generation failed: ${error.message}`);
        return new GenerateEncryptionKeyResult(null, `Key generation failed: ${error.message}`);
    }
}

/**
 * Recover an encryption key using OpenADP distributed secret sharing
 */
export async function recoverEncryptionKey(
    identity,
    password,
    serverInfos,
    threshold,
    authCodes
) {
    // Input validation
    if (!identity) {
        return new RecoverEncryptionKeyResult(null, "Identity cannot be null");
    }
    
    if (!identity.uid) {
        return new RecoverEncryptionKeyResult(null, "UID cannot be empty");
    }
    
    if (!identity.did) {
        return new RecoverEncryptionKeyResult(null, "DID cannot be empty");
    }
    
    if (!identity.bid) {
        return new RecoverEncryptionKeyResult(null, "BID cannot be empty");
    }

    if (!serverInfos || serverInfos.length === 0) {
        return new RecoverEncryptionKeyResult(null, "No OpenADP servers available");
    }

    if (!authCodes) {
        return new RecoverEncryptionKeyResult(null, "Authentication codes required");
    }

    console.log(`OpenADP: Recovery - Identity=${identity.toString()}`);

    try {
        // Step 1: Convert password to PIN
        const pin = passwordToPin(password);
        
        // Step 2: Initialize encrypted clients
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
        const uPoint = H(identity.uid, identity.did, identity.bid, pin);
        
        // Debug: Show the U point that we're using for recovery (convert to affine)
        const uPointAffine = unexpand(uPoint);
        
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
            
            // Get current guess number for this backup from the server
            let guessNum = 0; // Default to 0 for first guess (0-based indexing)
            try {
                const backups = await client.listBackups(identity.uid, false, null);
                // Find our backup in the list using the complete primary key (UID, DID, BID)
                for (const backup of backups) {
                    if (backup.uid === identity.uid && 
                        backup.did === identity.did && 
                        backup.bid === identity.bid) {
                        guessNum = parseInt(backup.num_guesses || 0);
                        break;
                    }
                }
            } catch (error) {
                console.warn(`Warning: Could not list backups from server ${i+1}: ${error.message}`);
            }
            
            // Try recovery with current guess number, retry once if guess number is wrong
            const recoverWithRetry = async () => {
                try {
                    const result = await client.recoverSecret(
                        authCode, identity.uid, identity.did, identity.bid, bBase64, guessNum, true
                    );
                    return { serverUrl, result };
                } catch (error) {
                    // If we get a guess number error, try to parse the expected number and retry
                    if (error.message && error.message.includes("expecting guess_num =")) {
                        try {
                            const errorStr = error.message;
                            const idx = errorStr.indexOf("expecting guess_num = ");
                            if (idx !== -1) {
                                const expectedStr = errorStr.substring(idx + "expecting guess_num = ".length);
                                const spaceIdx = expectedStr.indexOf(" ");
                                const expectedGuess = parseInt(spaceIdx !== -1 ? expectedStr.substring(0, spaceIdx) : expectedStr);
                                console.log(`Server ${i+1} (${serverUrl}): Retrying with expected guess_num = ${expectedGuess}`);
                                const retryResult = await client.recoverSecret(
                                    authCode, identity.uid, identity.did, identity.bid, bBase64, expectedGuess, true
                                );
                                return { serverUrl, result: retryResult };
                            } else {
                                throw error;
                            }
                        } catch (retryError) {
                            console.warn(`Server ${i+1} (${serverUrl}) recovery failed: ${error.message}`);
                            return { serverUrl, error };
                        }
                    } else {
                        console.warn(`Server ${i+1} (${serverUrl}) recovery failed: ${error.message}`);
                        return { serverUrl, error };
                    }
                }
            };
            
            recoveryPromises.push(recoverWithRetry());
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
                    
                    // Convert si_b back to point and then to share
                    try {
                        const siBBytes = Buffer.from(result.si_b, 'base64');
                        const siBPoint = pointDecompress(siBBytes);
                        const siBPoint2D = new Point2D(siBPoint.x, siBPoint.y);
                        
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
        
        // Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
        // This matches Go: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
        const recoveredSB4D = expand(recoveredSB);
        const originalSU = pointMul(rInv, recoveredSB4D);
        
        // Step 7: Derive same encryption key
        const encryptionKey = deriveEncKey(originalSU);
        console.log(`OpenADP: Successfully recovered encryption key`);
        
        return new RecoverEncryptionKeyResult(encryptionKey, null);
        
    } catch (error) {
        console.error(`OpenADP encryption key recovery failed: ${error.message}`);
        return new RecoverEncryptionKeyResult(null, `Key recovery failed: ${error.message}`);
    }
} 
