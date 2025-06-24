#!/usr/bin/env node

/**
 * OpenADP File Decryption Tool - JavaScript Version
 * 
 * This tool exactly matches the functionality of cmd/openadp-decrypt/main.go
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Buffer } from 'buffer';
import { Command } from 'commander';
import { recoverEncryptionKey } from './src/keygen.js';
import { getServers, getFallbackServerInfo, ServerInfo, OpenADPClient } from './src/client.js';

const VERSION = "1.0.0";
const NONCE_SIZE = 12; // AES-GCM nonce size

/**
 * Metadata represents the metadata stored with encrypted files
 */
class Metadata {
    constructor(servers, threshold, version, authCode, userId) {
        this.servers = servers;
        this.threshold = threshold;
        this.version = version;
        this.auth_code = authCode; // Single base auth code (32 bytes hex)
        this.user_id = userId;
    }
    
    static fromDict(data) {
        return new Metadata(
            data.servers,
            data.threshold,
            data.version,
            data.auth_code,
            data.user_id
        );
    }
}

function showHelp() {
    console.log(`OpenADP File Decryption Tool

USAGE:
    openadp-decrypt --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to decrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID override (will use metadata or prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs to override metadata servers
    --version              Show version information
    --help                 Show this help message

USER ID HANDLING:
    The tool will use the User ID in this priority order:
    1. Command line flag (-user-id)
    2. User ID stored in the encrypted file metadata
    3. OPENADP_USER_ID environment variable
    4. Interactive prompt

    You only need to specify a User ID if it's missing from the file metadata
    or if you want to override it for some reason.

EXAMPLES:
    # Decrypt a file using servers from metadata
    openadp-decrypt --file document.txt.enc

    # Decrypt using override servers
    openadp-decrypt --file document.txt.enc --servers "https://server1.com,https://server2.com"

    # Override user ID (useful for corrupted metadata)
    openadp-decrypt --file document.txt.enc --user-id "myuserid"

    # Use environment variables
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-decrypt --file document.txt.enc

The decrypted file will be saved without the .enc extension`);
}

function readUint32LE(buffer, offset) {
    return buffer.readUInt32LE(offset);
}

function sha256Hash(data) {
    return crypto.createHash('sha256').update(data).digest();
}

async function recoverEncryptionKeyWithServerInfo(filename, password, userId, baseAuthCode, serverInfos, threshold) {
    // Create AuthCodes structure from metadata
    const serverAuthCodes = {};
    for (const serverInfo of serverInfos) {
        // Derive server-specific code using SHA256 (same as GenerateAuthCodes)
        const combined = `${baseAuthCode}:${serverInfo.url}`;
        const hash = sha256Hash(Buffer.from(combined, 'utf8'));
        serverAuthCodes[serverInfo.url] = hash.toString('hex');
    }

    const authCodes = {
        baseAuthCode: baseAuthCode,
        serverAuthCodes: serverAuthCodes,
        userId: userId
    };

    // Recover encryption key using the full distributed protocol
    const result = await recoverEncryptionKey(filename, password, userId, serverInfos, threshold, authCodes);
    if (result.error) {
        throw new Error(`key recovery failed: ${result.error}`);
    }

    console.log("✅ Key recovered successfully");
    return result.encryptionKey;
}

function getAuthCodesFromMetadata(metadata) {
    if (!metadata.auth_code) {
        throw new Error("no authentication code found in metadata");
    }

    if (!metadata.user_id) {
        throw new Error("no user ID found in metadata");
    }

    return [metadata.auth_code, metadata.user_id];
}

async function decryptFile(inputFilename, password, userId, overrideServers) {
    // Determine output filename
    let outputFilename;
    if (inputFilename.endsWith('.enc')) {
        outputFilename = inputFilename.slice(0, -4); // Remove .enc
    } else {
        outputFilename = inputFilename + '.dec';
        console.log(`Warning: Input file doesn't end with .enc, using '${outputFilename}' for output`);
    }

    // Read the encrypted file
    let fileData;
    try {
        fileData = fs.readFileSync(inputFilename);
    } catch (error) {
        throw new Error(`failed to read input file: ${error.message}`);
    }

    // Validate file size
    const minSize = 4 + 1 + NONCE_SIZE + 1; // metadata_length + minimal_metadata + nonce + minimal_ciphertext
    if (fileData.length < minSize) {
        throw new Error(`file is too small to be a valid encrypted file (expected at least ${minSize} bytes, got ${fileData.length})`);
    }

    // Extract metadata length (first 4 bytes, little endian)
    const metadataLength = readUint32LE(fileData, 0);

    // Validate metadata length
    if (metadataLength > fileData.length - 4 - NONCE_SIZE) {
        throw new Error(`invalid metadata length ${metadataLength}`);
    }

    // Extract components: [metadata_length][metadata][nonce][encrypted_data]
    const metadataStart = 4;
    const metadataEnd = metadataStart + metadataLength;
    const nonceStart = metadataEnd;
    const nonceEnd = nonceStart + NONCE_SIZE;

    const metadataJSON = fileData.slice(metadataStart, metadataEnd);
    const nonce = fileData.slice(nonceStart, nonceEnd);
    const ciphertext = fileData.slice(nonceEnd);

    // Parse metadata
    let metadata;
    try {
        const metadataObj = JSON.parse(metadataJSON.toString('utf8'));
        metadata = Metadata.fromDict(metadataObj);
    } catch (error) {
        throw new Error(`failed to parse metadata: ${error.message}`);
    }

    let serverURLs = metadata.servers;
    if (!serverURLs || serverURLs.length === 0) {
        throw new Error("no server URLs found in metadata");
    }

    console.log(`Found metadata with ${serverURLs.length} servers, threshold ${metadata.threshold}`);
    console.log(`File version: ${metadata.version}`);

    // Show servers from metadata
    console.log("📋 Servers from encrypted file metadata:");
    for (let i = 0; i < serverURLs.length; i++) {
        console.log(`   ${i + 1}. ${serverURLs[i]}`);
    }

    // Use override servers if provided
    let serverInfos = [];
    if (overrideServers && overrideServers.length > 0) {
        console.log(`🔄 Overriding metadata servers with ${overrideServers.length} custom servers`);
        console.log("📋 Override servers:");
        for (let i = 0; i < overrideServers.length; i++) {
            console.log(`   ${i + 1}. ${overrideServers[i]}`);
        }

        // Get public keys directly from each override server via GetServerInfo
        console.log("   🔍 Querying override servers for public keys...");
        serverInfos = [];
        for (const url of overrideServers) {
            try {
                // Create a basic client to call GetServerInfo
                const basicClient = new OpenADPClient(url);
                const serverInfo = await basicClient.getServerInfo();

                // Extract public key from server info
                let publicKey = "";
                if (serverInfo && typeof serverInfo === 'object' && serverInfo.noise_nk_public_key) {
                    publicKey = "ed25519:" + serverInfo.noise_nk_public_key;
                }

                serverInfos.push(new ServerInfo(url, publicKey, "Unknown"));

                const keyStatus = publicKey ? "🔐 Public key available" : "❌ No public key";
                console.log(`   ✅ ${url} - ${keyStatus}`);
            } catch (error) {
                console.log(`   ⚠️  Failed to get server info from ${url}: ${error.message}`);
                // Add server without public key as fallback
                serverInfos.push(new ServerInfo(url, "", "Unknown"));
            }
        }

        serverURLs = overrideServers;
    } else {
        // Get server information from the secure registry (servers.json) instead of querying each server individually
        console.log("   🔍 Fetching server information from secure registry...");

        // Use the correct API endpoint for server discovery
        const serversURL = "https://servers.openadp.org/api/servers.json";

        // Try to get full server information including public keys from the registry
        let registryServerInfos;
        try {
            registryServerInfos = await getServers(serversURL);
            if (!registryServerInfos || registryServerInfos.length === 0) {
                throw new Error("No servers returned from registry");
            }
            console.log(`   ✅ Successfully fetched ${registryServerInfos.length} servers from registry`);
        } catch (error) {
            console.log(`   ⚠️  Failed to fetch from registry: ${error.message}`);
            console.log("   🔄 Falling back to hardcoded servers...");
            registryServerInfos = getFallbackServerInfo();
        }

        // Match servers from metadata with registry servers to get public keys
        serverInfos = [];
        for (const metadataURL of serverURLs) {
            // Find matching server in registry
            let matchedServer = null;
            for (const registryServer of registryServerInfos) {
                if (registryServer.url === metadataURL) {
                    matchedServer = registryServer;
                    break;
                }
            }

            if (matchedServer) {
                // Use server info from registry (includes public key)
                serverInfos.push(matchedServer);
                const keyStatus = matchedServer.publicKey ? "🔐 Public key available (from registry)" : "❌ No public key";
                console.log(`   ✅ ${metadataURL} - ${keyStatus}`);
            } else {
                // Server not found in registry, add without public key as fallback
                console.log(`   ⚠️  Server ${metadataURL} not found in registry, adding without public key`);
                serverInfos.push(new ServerInfo(metadataURL, "", "Unknown"));
            }
        }
    }

    // Check authentication requirements
    if (!metadata.auth_code) {
        console.log("ℹ️  File was encrypted without authentication (legacy), but using auth for decryption");
    } else {
        console.log("🔒 File was encrypted with authentication (standard)");
    }

    // Extract authentication codes and user ID from metadata
    let baseAuthCode, userIdFromMetadata;
    try {
        [baseAuthCode, userIdFromMetadata] = getAuthCodesFromMetadata(metadata);
    } catch (error) {
        throw new Error(`failed to extract auth codes: ${error.message}`);
    }

    // Determine final user ID (priority: flag > metadata > environment > prompt)
    let finalUserId = "";
    if (userId) {
        finalUserId = userId;
        console.log(`🔐 Using user ID from command line: ${finalUserId}`);
    } else if (userIdFromMetadata) {
        finalUserId = userIdFromMetadata;
        console.log(`🔐 Using user ID from file metadata: ${finalUserId}`);
    } else if (process.env.OPENADP_USER_ID) {
        finalUserId = process.env.OPENADP_USER_ID;
        console.log("🔐 Using user ID from environment variable");
    } else {
        // TODO: Implement user input prompt for Node.js
        throw new Error("User ID required. Use -user-id flag, file metadata, or OPENADP_USER_ID environment variable");
    }

    // Recover encryption key using OpenADP
    console.log("🔄 Recovering encryption key from OpenADP servers...");
    const encKey = await recoverEncryptionKeyWithServerInfo(outputFilename, password, finalUserId, baseAuthCode, serverInfos, metadata.threshold);

    // Decrypt the file using metadata as additional authenticated data
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, nonce);
    decipher.setAAD(metadataJSON); // Use metadata as AAD, matching Go/Python
    
    // Split ciphertext and auth tag (last 16 bytes)
    const actualCiphertext = ciphertext.slice(0, -16);
    const authTag = ciphertext.slice(-16);
    
    decipher.setAuthTag(authTag);
    
    let plaintext;
    try {
        let decrypted = decipher.update(actualCiphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        plaintext = decrypted;
    } catch (error) {
        // AEAD authentication failure should always be fatal
        throw new Error(`decryption failed: ${error.message} (wrong password or corrupted file)`);
    }

    // Write the decrypted file
    try {
        fs.writeFileSync(outputFilename, plaintext);
    } catch (error) {
        throw new Error(`failed to write output file: ${error.message}`);
    }

    console.log(`📁 Input:  ${inputFilename} (${fileData.length} bytes)`);
    console.log(`📁 Output: ${outputFilename} (${plaintext.length} bytes)`);
    console.log(`🌐 Servers: ${serverURLs.length} servers used`);
    console.log(`🎯 Threshold: ${metadata.threshold}-of-${serverURLs.length} recovery`);
    console.log(`🔐 Authentication: Enabled (Authentication Codes)`);

    // Show final server list used for recovery
    console.log("📋 Servers used for decryption:");
    for (let i = 0; i < serverURLs.length; i++) {
        console.log(`   ${i + 1}. ${serverURLs[i]}`);
    }
}

async function main() {
    const program = new Command();
    
    program
        .name('openadp-decrypt')
        .description('OpenADP File Decryption Tool')
        .version(VERSION);
    
    program
        .option('--file <path>', 'File to decrypt (required)')
        .option('--password <password>', 'Password for key derivation (will prompt if not provided)')
        .option('--user-id <id>', 'User ID override (will use metadata or prompt if not provided)')
        .option('--servers <urls>', 'Comma-separated list of server URLs to override metadata servers')
        .parse();
    
    const options = program.opts();
    
    if (!options.file) {
        console.log("Error: --file is required");
        showHelp();
        process.exit(1);
    }
    
    // Check if input file exists
    if (!fs.existsSync(options.file)) {
        console.log(`Error: Input file '${options.file}' not found.`);
        process.exit(1);
    }
    
    // Get password (priority: flag > environment > prompt)
    let passwordStr = "";
    if (options.password) {
        passwordStr = options.password;
        console.log("⚠️  Warning: Password provided via command line (visible in process list)");
    } else if (process.env.OPENADP_PASSWORD) {
        passwordStr = process.env.OPENADP_PASSWORD;
        console.log("Using password from environment variable");
    } else {
        // TODO: Implement secure password prompt for Node.js
        console.log("Error: Password required. Use --password flag or OPENADP_PASSWORD environment variable");
        process.exit(1);
    }
    
    // Parse override servers if provided
    let overrideServerURLs = null;
    if (options.servers) {
        overrideServerURLs = options.servers.split(',').map(url => url.trim());
    }
    
    // Decrypt the file
    try {
        await decryptFile(options.file, passwordStr, options.userId, overrideServerURLs);
        console.log("✅ File decrypted successfully!");
    } catch (error) {
        console.log(`❌ Decryption failed: ${error.message}`);
        process.exit(1);
    }
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
}); 
