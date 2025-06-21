/**
 * OpenADP Key Generation and Management
 * 
 * This module provides key generation and management functions:
 * - Encryption key generation and recovery
 * - Identifier derivation
 * - Authentication code management
 * - Password-to-PIN conversion
 */

import crypto from 'crypto';
import { Point2D, G, hkdf, ShamirSecretSharing, generateAuthCodes, passwordToPin } from './crypto.js';

/**
 * Generate a new encryption key with distributed shares
 */
function generateEncryptionKey(threshold, numShares, password, serverIds) {
    if (threshold > numShares) {
        throw new Error('Threshold cannot be greater than number of shares');
    }
    if (threshold < 1) {
        throw new Error('Threshold must be at least 1');
    }
    if (serverIds.length !== numShares) {
        throw new Error('Number of server IDs must match number of shares');
    }

    // Generate a random 256-bit encryption key
    const encryptionKey = crypto.randomBytes(32);
    
    // Split the key using Shamir secret sharing
    const shares = ShamirSecretSharing.split(encryptionKey, threshold, numShares);
    
    // Convert shares to byte arrays for storage
    const shareBytes = shares.map(share => {
        const shareData = new Uint8Array(36); // 4 bytes for x, 32 bytes for y
        shareData[0] = share.x & 0xFF;
        shareData[1] = (share.x >> 8) & 0xFF;
        shareData[2] = (share.x >> 16) & 0xFF;
        shareData[3] = (share.x >> 24) & 0xFF;
        
        // Convert y to bytes (little-endian)
        let y = share.y;
        for (let i = 4; i < 36; i++) {
            shareData[i] = Number(y & 0xFFn);
            y >>= 8n;
        }
        
        return shareData;
    });
    
    // Generate identifiers for the secret
    const identifiers = deriveIdentifiers(encryptionKey, password);
    
    // Generate authentication codes for each server
    const authCodes = generateAuthCodes(encryptionKey, serverIds);
    
    return {
        encryptionKey: encryptionKey,
        shares: shareBytes,
        identifiers: identifiers,
        authCodes: authCodes,
        threshold: threshold,
        numShares: numShares
    };
}

/**
 * Recover an encryption key from shares
 */
function recoverEncryptionKey(shareBytes, threshold) {
    if (shareBytes.length < threshold) {
        throw new Error(`Insufficient shares: ${shareBytes.length} < ${threshold}`);
    }

    // Convert byte arrays back to shares
    const shares = shareBytes.slice(0, threshold).map(shareData => {
        if (shareData.length !== 36) {
            throw new Error('Invalid share data length');
        }
        
        const x = shareData[0] | (shareData[1] << 8) | (shareData[2] << 16) | (shareData[3] << 24);
        
        // Convert bytes back to y (little-endian, matching the encoding)
        let y = 0n;
        for (let i = 4; i < 36; i++) {
            y = y | (BigInt(shareData[i]) << BigInt((i - 4) * 8));
        }
        
        return { x: x, y: y };
    });
    
    // Recover the secret using Lagrange interpolation
    const encryptionKey = ShamirSecretSharing.recover(shares);
    
    return encryptionKey;
}

/**
 * Derive identifiers for a secret
 */
function deriveIdentifiers(encryptionKey, password) {
    // Combine encryption key and password for identifier derivation
    const input = Buffer.concat([
        Buffer.from(encryptionKey),
        Buffer.from(password, 'utf8')
    ]);
    
    // Derive secret ID using HKDF
    const secretId = hkdf(input, null, Buffer.from('OpenADP-SecretID'), 32);
    
    // Derive backup ID using HKDF
    const backupId = hkdf(input, null, Buffer.from('OpenADP-BackupID'), 32);
    
    // Convert to hex strings for use as identifiers
    return {
        secretId: secretId.toString('hex'),
        backupId: backupId.toString('hex')
    };
}

/**
 * Generate authentication codes for multiple servers
 */
function generateServerAuthCodes(encryptionKey, serverIds) {
    return generateAuthCodes(encryptionKey, serverIds);
}

/**
 * Convert password to PIN for user verification
 */
function convertPasswordToPin(password, salt, iterations = 100000) {
    return passwordToPin(password, salt, iterations);
}

/**
 * Generate a secure salt for password operations
 */
function generateSalt(length = 32) {
    return crypto.randomBytes(length);
}

/**
 * Derive a key from password using PBKDF2
 */
function deriveKeyFromPassword(password, salt, iterations = 100000, keyLength = 32) {
    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
}

/**
 * Generate a secure random identifier
 */
function generateRandomIdentifier(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Validate share data format
 */
function validateShareData(shareData) {
    if (!shareData || shareData.length !== 36) {
        return false;
    }
    
    try {
        // Extract x coordinate
        const x = shareData[0] | (shareData[1] << 8) | (shareData[2] << 16) | (shareData[3] << 24);
        
        // Extract y coordinate
        let y = 0n;
        for (let i = 35; i >= 4; i--) {
            y = (y << 8n) + BigInt(shareData[i]);
        }
        
        // Basic validation - x should be in valid range for share index
        return x > 0 && x <= 255 && y >= 0n;
    } catch {
        return false;
    }
}

/**
 * Create a backup package containing all necessary recovery information
 */
function createBackupPackage(encryptionKey, shares, identifiers, authCodes, metadata = {}) {
    const backup = {
        version: '1.0',
        timestamp: new Date().toISOString(),
        identifiers: identifiers,
        shares: shares.map(share => Array.from(share)),
        authCodes: Object.fromEntries(
            Object.entries(authCodes).map(([key, value]) => [key, Array.from(value)])
        ),
        metadata: metadata
    };
    
    // Sign the backup with the encryption key for integrity
    const backupData = Buffer.from(JSON.stringify(backup), 'utf8');
    const signature = crypto.createHmac('sha256', encryptionKey).update(backupData).digest();
    
    return {
        backup: backup,
        signature: Array.from(signature)
    };
}

/**
 * Verify and restore a backup package
 */
function restoreBackupPackage(backupPackage, encryptionKey) {
    const { backup, signature } = backupPackage;
    
    // Verify signature
    const backupData = Buffer.from(JSON.stringify(backup), 'utf8');
    const expectedSignature = crypto.createHmac('sha256', encryptionKey).update(backupData).digest();
    const providedSignature = new Uint8Array(signature);
    
    if (!crypto.timingSafeEqual(expectedSignature, providedSignature)) {
        throw new Error('Backup package signature verification failed');
    }
    
    // Convert arrays back to Uint8Arrays
    const shares = backup.shares.map(share => new Uint8Array(share));
    const authCodes = Object.fromEntries(
        Object.entries(backup.authCodes).map(([key, value]) => [key, new Uint8Array(value)])
    );
    
    return {
        version: backup.version,
        timestamp: backup.timestamp,
        identifiers: backup.identifiers,
        shares: shares,
        authCodes: authCodes,
        metadata: backup.metadata
    };
}

/**
 * Generate a recovery phrase from the encryption key
 */
function generateRecoveryPhrase(encryptionKey, wordList = null) {
    // Use a simple word list if none provided (for demo purposes)
    const defaultWordList = [
        'apple', 'banana', 'cherry', 'date', 'elderberry', 'fig', 'grape', 'honeydew',
        'kiwi', 'lemon', 'mango', 'nectarine', 'orange', 'papaya', 'quince', 'raspberry',
        'strawberry', 'tangerine', 'ugli', 'vanilla', 'watermelon', 'xigua', 'yellow', 'zucchini'
    ];
    
    const words = wordList || defaultWordList;
    const phrase = [];
    
    // Convert key to indices
    for (let i = 0; i < encryptionKey.length; i += 2) {
        const value = encryptionKey[i] | (encryptionKey[i + 1] << 8);
        const wordIndex = value % words.length;
        phrase.push(words[wordIndex]);
    }
    
    return phrase.join(' ');
}

/**
 * Recover encryption key from recovery phrase
 */
function recoverFromRecoveryPhrase(phrase, wordList = null) {
    // Use the same default word list
    const defaultWordList = [
        'apple', 'banana', 'cherry', 'date', 'elderberry', 'fig', 'grape', 'honeydew',
        'kiwi', 'lemon', 'mango', 'nectarine', 'orange', 'papaya', 'quince', 'raspberry',
        'strawberry', 'tangerine', 'ugli', 'vanilla', 'watermelon', 'xigua', 'yellow', 'zucchini'
    ];
    
    const words = wordList || defaultWordList;
    const phraseWords = phrase.split(' ');
    
    if (phraseWords.length !== 16) {
        throw new Error('Recovery phrase must contain exactly 16 words');
    }
    
    const keyBytes = new Uint8Array(32);
    
    for (let i = 0; i < phraseWords.length; i++) {
        const wordIndex = words.indexOf(phraseWords[i]);
        if (wordIndex === -1) {
            throw new Error(`Unknown word in recovery phrase: ${phraseWords[i]}`);
        }
        
        const byteIndex = i * 2;
        keyBytes[byteIndex] = wordIndex & 0xFF;
        keyBytes[byteIndex + 1] = (wordIndex >> 8) & 0xFF;
    }
    
    return keyBytes;
}

export {
    generateEncryptionKey,
    recoverEncryptionKey,
    deriveIdentifiers,
    generateServerAuthCodes,
    convertPasswordToPin,
    generateSalt,
    deriveKeyFromPassword,
    generateRandomIdentifier,
    validateShareData,
    createBackupPackage,
    restoreBackupPackage,
    generateRecoveryPhrase,
    recoverFromRecoveryPhrase
}; 