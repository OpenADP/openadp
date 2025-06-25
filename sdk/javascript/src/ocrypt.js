/**
 * Ocrypt - Nation-state resistant password hashing using OpenADP distributed cryptography
 * 
 * This module provides a simple 2-function API for distributed password hashing
 * using OpenADP's Oblivious Pseudo Random Function (OPRF) cryptography.
 * 
 * This package replaces traditional password hashing functions like bcrypt, scrypt,
 * Argon2, and PBKDF2 with distributed threshold cryptography that is resistant to
 * nation-state attacks and provides automatic backup refresh.
 * 
 * Key Features:
 * - Nation-state resistant security through distributed servers
 * - Built-in guess limiting across all servers
 * - Automatic backup refresh with crash safety
 * - Two-phase commit for reliable backup updates
 * - Generic secret protection (not just passwords)
 * 
 * @example
 * import { register, recover } from '@openadp/ocrypt';
 * 
 * // Register a secret
 * const metadata = await register('alice@example.com', 'my_app', secret, 'password123', 10);
 * 
 * // Later, recover the secret
 * const { secret: recoveredSecret, remaining, updatedMetadata } = await recover(metadata, 'password123');
 */

import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from 'crypto';
import { Buffer } from 'buffer';

// Import real OpenADP components
import { generateEncryptionKey, recoverEncryptionKey, Identity } from './keygen.js';
import { getServers, getFallbackServerInfo } from './client.js';

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
 * @param {Uint8Array|Buffer} longTermSecret - User-provided secret to protect (any byte sequence)
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
        serverInfos = serverInfos.sort(() => 0.5 - Math.random()).slice(0, 15);
        console.log(`   �� Randomly selected 15 servers for load balancing`);
    }

    // Step 2: Generate encryption key using REAL OpenADP protocol
    console.log(`🔄 Using backup ID: ${backupID}`);
    console.log('🔑 Generating encryption key using OpenADP servers...');

    // Create Identity from Ocrypt parameters
    const identity = new Identity(
        userID,   // UID = userID (user identifier)
        appID,    // DID = appID (application identifier, serves as device ID)
        backupID  // BID = backupID (managed by Ocrypt: "even"/"odd")
    );
    
    try {
        const result = await generateEncryptionKey(
            identity,
            pin,
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
 * @param {Uint8Array|Buffer} metadataBytes - Metadata blob from register()
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
        updatedMetadata = metadataBytes; // Use original metadata
    }

    return { secret, remaining, updatedMetadata };
}

/**
 * Recovers a secret without attempting backup refresh
 * @private
 */
async function recoverWithoutRefresh(metadataBytes, pin) {
    // Parse metadata
    let metadata;
    try {
        const metadataStr = new TextDecoder().decode(metadataBytes);
        metadata = JSON.parse(metadataStr);
    } catch (error) {
        throw new OcryptError(`Invalid metadata format: ${error.message}`, 'INVALID_METADATA');
    }

    console.log(`🔍 Recovering secret for user: ${metadata.user_id}, app: ${metadata.app_id}, bid: ${metadata.backup_id}`);

    // Get server information using REAL server discovery
    console.log('🌐 Getting server information from registry...');
    let allServers;
    try {
        allServers = await getServers("https://servers.openadp.org/api/servers.json");
    } catch (error) {
        console.log(`   ⚠️  Failed to fetch from registry: ${error.message}`);
        allServers = getFallbackServerInfo();
    }

    // Match servers from metadata with registry
    const serverInfos = [];
    for (const serverURL of metadata.servers) {
        const serverInfo = allServers.find(s => s.url === serverURL);
        if (serverInfo) {
            serverInfos.push(serverInfo);
            console.log(`   ✅ ${serverURL} - matched in registry`);
        }
    }

    if (serverInfos.length === 0) {
        throw new OcryptError('No servers from metadata found in registry', 'SERVERS_NOT_FOUND');
    }

    // Recover encryption key from OpenADP using REAL protocol
    console.log('🔑 Recovering encryption key from OpenADP servers...');
    
    // Create Identity from metadata
    const identity = new Identity(
        metadata.user_id,   // UID = userID
        metadata.app_id,    // DID = appID
        metadata.backup_id  // BID = backupID
    );
    
    // Reconstruct auth codes
    const authCodes = {
        baseAuthCode: metadata.auth_code,
        serverAuthCodes: {},
        userID: metadata.user_id
    };

    // Generate server-specific auth codes
    for (const serverURL of metadata.servers) {
        const combined = `${metadata.auth_code}:${serverURL}`;
        const hash = sha256(new TextEncoder().encode(combined));
        authCodes.serverAuthCodes[serverURL] = Buffer.from(hash).toString('hex');
    }
    
    try {
        const result = await recoverEncryptionKey(
            identity, 
            pin, 
            serverInfos, 
            metadata.threshold, 
            authCodes
        );
        
        if (result.error) {
            throw new Error(result.error);
        }
        
        console.log('✅ Successfully recovered encryption key');

        // Unwrap the long-term secret using WebCrypto API
        console.log('🔐 Validating PIN by unwrapping secret...');
        const secret = await unwrapSecret(metadata.wrapped_long_term_secret, result.encryptionKey);
        
        console.log('✅ PIN validation successful - secret unwrapped');

        return { secret, remaining: 0 }; // Success = 0 remaining guesses in this implementation
    } catch (error) {
        throw new OcryptError(`OpenADP recovery failed: ${error.message}`, 'OPENADP_RECOVERY_FAILED');
    }
}

/**
 * Implements two-phase commit for backup refresh
 * @private
 */
async function registerWithCommitInternal(userID, appID, longTermSecret, pin, maxGuesses, newBackupID) {
    // Phase 1: PREPARE - Register new backup
    console.log('📋 Phase 1: PREPARE - Registering new backup...');
    const newMetadata = await registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, newBackupID);
    console.log('✅ Phase 1 complete: New backup registered');

    // Phase 2: COMMIT - Verify new backup works
    console.log('📋 Phase 2: COMMIT - Verifying new backup...');
    await recoverWithoutRefresh(newMetadata, pin);
    console.log('✅ Phase 2 complete: New backup verified and committed');

    return newMetadata;
}

/**
 * Generates the next backup ID using smart strategies
 * @private
 */
function generateNextBackupID(currentBackupID) {
    switch (currentBackupID) {
        case 'even':
            return 'odd';
        case 'odd':
            return 'even';
        default:
            // For version numbers like v1, v2, etc.
            if (currentBackupID.startsWith('v') && currentBackupID.length > 1) {
                const versionStr = currentBackupID.slice(1);
                const version = parseInt(versionStr, 10);
                if (version > 0) {
                    return `v${version + 1}`;
                }
            }
            
            // Fallback: append timestamp
            const timestamp = Math.floor(Date.now() / 1000);
            return `${currentBackupID}_v${timestamp}`;
    }
}

/**
 * Encrypts a secret using AES-256-GCM with WebCrypto API
 * @private
 */
async function wrapSecret(secret, key) {
    try {
        // Convert key to WebCrypto format
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        // Generate random nonce
        const nonce = crypto.getRandomValues(new Uint8Array(12));

        // Encrypt with AES-GCM
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            secret
        );

        // Split ciphertext and tag (WebCrypto appends tag)
        const encryptedArray = new Uint8Array(encrypted);
        const tagSize = 16; // AES-GCM tag is always 16 bytes
        const ciphertext = encryptedArray.slice(0, -tagSize);
        const tag = encryptedArray.slice(-tagSize);

        return {
            nonce: Buffer.from(nonce).toString('base64'),
            ciphertext: Buffer.from(ciphertext).toString('base64'),
            tag: Buffer.from(tag).toString('base64')
        };
    } catch (error) {
        throw new OcryptError(`Secret wrapping failed: ${error.message}`, 'WRAPPING_FAILED');
    }
}

/**
 * Decrypts a secret using AES-256-GCM with WebCrypto API
 * @private
 */
async function unwrapSecret(wrapped, key) {
    try {
        // Convert key to WebCrypto format
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const nonce = Buffer.from(wrapped.nonce, 'base64');
        const ciphertext = Buffer.from(wrapped.ciphertext, 'base64');
        const tag = Buffer.from(wrapped.tag, 'base64');

        // Reconstruct full encrypted data (ciphertext + tag)
        const encryptedData = new Uint8Array(ciphertext.length + tag.length);
        encryptedData.set(ciphertext);
        encryptedData.set(tag, ciphertext.length);

        // Decrypt with AES-GCM
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            encryptedData
        );

        return new Uint8Array(decrypted);
    } catch (error) {
        throw new OcryptError(`Invalid PIN or corrupted data: ${error.message}`, 'INVALID_PIN');
    }
} 