/**
 * Ocrypt - Nation-state resistant password hashing using OpenADP distributed cryptography
 * Browser-compatible version using WebCrypto API
 * 
 * This library provides a simple interface that replaces traditional password hashing
 * functions like bcrypt, scrypt, Argon2, and PBKDF2 with distributed threshold cryptography.
 * 
 * Instead of storing password hashes locally, secrets are protected using a network of
 * independent OpenADP servers that implement threshold cryptography protocols.
 * 
 * @example Basic usage:
 * // Register (protect a secret)
 * const metadata = await register('user123', 'myapp', longTermSecret, 'password123', 10);
 * 
 * // Recover (retrieve the secret)
 * const { secret: recoveredSecret, remaining, updatedMetadata } = await recover(metadata, 'password123');
 */

import { sha256 } from '@noble/hashes/sha256';

// Import browser-compatible OpenADP components
import { generateEncryptionKey, recoverEncryptionKey } from './keygen.js';
import { getServers, getFallbackServerInfo } from './client.browser.js';

/**
 * Browser-compatible random bytes generation
 */
function randomBytes(size) {
    const bytes = new Uint8Array(size);
    crypto.getRandomValues(bytes);
    return bytes;
}

/**
 * Custom error class for Ocrypt operations
 */
export class OcryptError extends Error {
    constructor(message, code = null) {
        super(code ? `Ocrypt ${code}: ${message}` : `Ocrypt error: ${message}`);
        this.name = 'OcryptError';
        this.code = code;
    }
}

/**
 * Register protects a long-term secret using OpenADP distributed cryptography.
 * 
 * This function provides a simple interface that replaces traditional password hashing
 * functions like bcrypt, scrypt, Argon2, and PBKDF2 with distributed threshold cryptography.
 * 
 * @param {string} userID - Unique identifier for the user (e.g., email, username)
 * @param {string} appID - Application identifier to namespace secrets per app
 * @param {Uint8Array} longTermSecret - User-provided secret to protect (any byte sequence)
 * @param {string} pin - Password/PIN that will unlock the secret
 * @param {number} [maxGuesses=10] - Maximum wrong PIN attempts before lockout
 * @returns {Promise<Uint8Array>} metadata - Opaque blob to store alongside user record
 * @throws {OcryptError} Any error that occurred during registration
 */
export async function register(userID, appID, longTermSecret, pin, maxGuesses = 10) {
    return await registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, 'even');
}

/**
 * Internal implementation that allows specifying backup ID
 * @private
 */
async function registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, backupID) {
    // Input validation
    if (!userID || typeof userID !== 'string') {
        throw new OcryptError('user_id must be a non-empty string', 'INVALID_INPUT');
    }
    if (!appID || typeof appID !== 'string') {
        throw new OcryptError('app_id must be a non-empty string', 'INVALID_INPUT');
    }
    if (!longTermSecret || longTermSecret.length === 0) {
        throw new OcryptError('long_term_secret cannot be empty', 'INVALID_INPUT');
    }
    if (!pin || typeof pin !== 'string') {
        throw new OcryptError('pin must be a non-empty string', 'INVALID_INPUT');
    }
    if (maxGuesses <= 0) {
        maxGuesses = 10; // Default value
    }

    console.log(`🔐 Protecting secret for user: ${userID}`);
    console.log(`📱 Application: ${appID}`);
    console.log(`🔑 Secret length: ${longTermSecret.length} bytes`);

    // Step 1: Discover OpenADP servers using REAL server discovery
    console.log('🌐 Discovering OpenADP servers...');
    let serverInfos;
    try {
        serverInfos = await getServers("https://servers.openadp.org/api/servers.json");
        if (!serverInfos || serverInfos.length === 0) {
            throw new Error("No servers returned from registry");
        }
        console.log(`   ✅ Successfully fetched ${serverInfos.length} servers from registry`);
    } catch (error) {
        console.log(`   ⚠️  Failed to fetch from registry: ${error.message}`);
        console.log('   🔄 Falling back to hardcoded servers...');
        serverInfos = getFallbackServerInfo();
        console.log(`   Fallback servers: ${serverInfos.length}`);
    }
    
    if (!serverInfos || serverInfos.length === 0) {
        throw new OcryptError('No OpenADP servers available', 'NO_SERVERS');
    }

    // Random server selection for load balancing (max 15 servers for performance)
    if (serverInfos.length > 15) {
        // Fisher-Yates shuffle using crypto.getRandomValues
        for (let i = serverInfos.length - 1; i > 0; i--) {
            const randomBytes = crypto.getRandomValues(new Uint8Array(4));
            const randomValue = new DataView(randomBytes.buffer).getUint32(0);
            const j = randomValue % (i + 1);
            [serverInfos[i], serverInfos[j]] = [serverInfos[j], serverInfos[i]];
        }
        serverInfos = serverInfos.slice(0, 15);
        console.log(`   🎲 Randomly selected 15 servers for load balancing`);
    }

    // Step 2: Generate encryption key using REAL OpenADP protocol
    console.log(`🔄 Using backup ID: ${backupID}`);
    console.log('🔑 Generating encryption key using OpenADP servers...');

    // Create synthetic filename for BID derivation
    const filename = `${userID}#${appID}#${backupID}`;
    
    try {
        const result = await generateEncryptionKey(
            filename,
            pin,
            userID,
            maxGuesses,
            0, // No expiration by default
            serverInfos
        );
        
        if (result.error) {
            throw new Error(result.error);
        }

        console.log(`✅ Generated encryption key with ${result.serverUrls.length} servers`);

        // Step 3: Wrap the long-term secret with AES-256-GCM using WebCrypto API
        console.log('🔐 Wrapping long-term secret...');
        const wrappedSecret = await wrapSecret(longTermSecret, result.encryptionKey);

        // Step 4: Create metadata
        const metadata = {
            // Standard openadp-encrypt metadata
            servers: result.serverUrls,
            threshold: result.threshold,
            version: '1.0',
            auth_code: result.authCodes.baseAuthCode,
            user_id: userID,
            
            // Ocrypt-specific additions
            wrapped_long_term_secret: wrappedSecret,
            backup_id: backupID,
            app_id: appID,
            max_guesses: maxGuesses,
            ocrypt_version: '1.0'
        };

        const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));

        console.log(`📦 Created metadata (${metadataBytes.length} bytes)`);
        console.log(`🎯 Threshold: ${result.threshold}-of-${result.serverUrls.length} recovery`);

        return metadataBytes;
    } catch (error) {
        throw new OcryptError(`OpenADP registration failed: ${error.message}`, 'OPENADP_FAILED');
    }
}

/**
 * Recover recovers a secret from Ocrypt metadata with automatic backup refresh.
 * 
 * This function implements a two-phase commit pattern for safe backup refresh:
 * 1. Recovers the secret using existing backup
 * 2. Attempts to refresh backup with opposite backup ID
 * 3. Returns updated metadata if refresh succeeds, original if it fails
 * 
 * @param {Uint8Array} metadataBytes - Metadata blob from register()
 * @param {string} pin - Password/PIN to unlock the secret
 * @returns {Promise<{secret: Uint8Array, remaining: number, updatedMetadata: Uint8Array}>}
 * @throws {OcryptError} Any error that occurred during recovery
 */
export async function recover(metadataBytes, pin) {
    // Input validation
    if (!metadataBytes || metadataBytes.length === 0) {
        throw new OcryptError('metadata cannot be empty', 'INVALID_INPUT');
    }
    if (!pin || typeof pin !== 'string') {
        throw new OcryptError('pin must be a non-empty string', 'INVALID_INPUT');
    }

    // Step 1: Recover with existing backup
    console.log('📋 Step 1: Recovering with existing backup...');
    const { secret, remaining } = await recoverWithoutRefresh(metadataBytes, pin);

    // Step 2: Attempt backup refresh using two-phase commit
    let updatedMetadata;
    
    try {
        // Parse metadata to get current backup ID
        const metadataStr = new TextDecoder().decode(metadataBytes);
        const metadata = JSON.parse(metadataStr);

        console.log(`📋 Step 2: Attempting backup refresh for BID: ${metadata.backup_id}`);
        
        const newBackupID = generateNextBackupID(metadata.backup_id);
        console.log(`🔄 Two-phase commit: ${metadata.backup_id} → ${newBackupID}`);

        const refreshedMetadata = await registerWithCommitInternal(
            metadata.user_id, 
            metadata.app_id, 
            secret, 
            pin, 
            metadata.max_guesses, 
            newBackupID
        );
        
        console.log(`✅ Backup refresh successful: ${metadata.backup_id} → ${newBackupID}`);
        updatedMetadata = refreshedMetadata;
    } catch (error) {
        console.log(`⚠️  Backup refresh failed: ${error.message}`);
        console.log('✅ Recovery still successful with existing backup');
        updatedMetadata = metadataBytes;
    }

    return {
        secret,
        remaining,
        updatedMetadata
    };
}

/**
 * Internal recovery without backup refresh
 * @private
 */
async function recoverWithoutRefresh(metadataBytes, pin) {
    // Parse metadata
    const metadataStr = new TextDecoder().decode(metadataBytes);
    const metadata = JSON.parse(metadataStr);

    console.log(`🔓 Recovering secret for user: ${metadata.user_id}`);
    console.log(`📱 Application: ${metadata.app_id}`);
    console.log(`🔄 Backup ID: ${metadata.backup_id}`);

    // Create synthetic filename for BID derivation
    const filename = `${metadata.user_id}#${metadata.app_id}#${metadata.backup_id}`;

    try {
        // Step 1: Recover encryption key using REAL OpenADP protocol
        console.log('🔑 Recovering encryption key from OpenADP servers...');
        const result = await recoverEncryptionKey(
            filename,
            pin,
            metadata.user_id,
            metadata.servers,
            metadata.threshold,
            metadata.auth_code
        );

        if (result.error) {
            throw new Error(result.error);
        }

        console.log(`✅ Recovered encryption key (${result.remaining} attempts remaining)`);

        // Step 2: Unwrap the long-term secret
        console.log('🔓 Unwrapping long-term secret...');
        const longTermSecret = await unwrapSecret(metadata.wrapped_long_term_secret, result.encryptionKey);

        console.log(`🎉 Successfully recovered ${longTermSecret.length}-byte secret`);

        return {
            secret: longTermSecret,
            remaining: result.remaining
        };
    } catch (error) {
        throw new OcryptError(`OpenADP recovery failed: ${error.message}`, 'OPENADP_FAILED');
    }
}

/**
 * Internal registration with commit (for backup refresh)
 * @private
 */
async function registerWithCommitInternal(userID, appID, longTermSecret, pin, maxGuesses, newBackupID) {
    try {
        return await registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, newBackupID);
    } catch (error) {
        throw new OcryptError(`Backup refresh failed: ${error.message}`, 'REFRESH_FAILED');
    }
}

/**
 * Generate next backup ID for rotation
 * @private
 */
function generateNextBackupID(currentBackupID) {
    // Simple alternating pattern for backup rotation
    const backupIDs = ['even', 'odd'];
    const currentIndex = backupIDs.indexOf(currentBackupID);
    
    if (currentIndex === -1) {
        // Unknown backup ID, default to 'even'
        return 'even';
    }
    
    // Return the opposite backup ID
    return backupIDs[1 - currentIndex];
}

/**
 * Wrap a secret using AES-256-GCM with WebCrypto API
 * @private
 */
async function wrapSecret(secret, key) {
    const iv = randomBytes(12); // 96-bit IV for GCM
    
    try {
        // Import key for WebCrypto
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        // Encrypt using WebCrypto AES-GCM
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            cryptoKey,
            secret
        );

        // Combine IV + encrypted data
        const wrapped = new Uint8Array(iv.length + encrypted.byteLength);
        wrapped.set(iv);
        wrapped.set(new Uint8Array(encrypted), iv.length);

        return Array.from(wrapped); // Convert to regular array for JSON serialization
    } catch (error) {
        throw new Error(`Secret wrapping failed: ${error.message}`);
    }
}

/**
 * Unwrap a secret using AES-256-GCM with WebCrypto API
 * @private
 */
async function unwrapSecret(wrapped, key) {
    const wrappedBytes = new Uint8Array(wrapped);
    const iv = wrappedBytes.slice(0, 12);
    const encrypted = wrappedBytes.slice(12);
    
    try {
        // Import key for WebCrypto
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        // Decrypt using WebCrypto AES-GCM
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            cryptoKey,
            encrypted
        );

        return new Uint8Array(decrypted);
    } catch (error) {
        throw new Error(`Secret unwrapping failed: ${error.message}`);
    }
} 