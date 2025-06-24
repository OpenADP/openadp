#!/usr/bin/env node

/**
 * OpenADP File Encryption Tool - JavaScript Version
 * 
 * This tool exactly matches the functionality of cmd/openadp-encrypt/main.go
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import { Buffer } from 'buffer';
import { Command } from 'commander';
import { generateEncryptionKey } from './src/keygen.js';
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
    
    toDict() {
        return {
            servers: this.servers,
            threshold: this.threshold,
            version: this.version,
            auth_code: this.auth_code,
            user_id: this.user_id
        };
    }
}

function showHelp() {
    console.log(`OpenADP File Encryption Tool

USAGE:
    openadp-encrypt --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to encrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID for secret ownership (will prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs (optional)
    --servers-url <url>    URL to scrape for server list (default: https://servers.openadp.org/api/servers.json)
    --version              Show version information
    --help                 Show this help message

USER ID SECURITY:
    Your User ID uniquely identifies your secrets on the servers. It is critical that:
    • You use the same User ID for all your files
    • You keep your User ID private (anyone with it can overwrite your secrets)
    • You choose a unique User ID that others won't guess
    • You remember your User ID for future decryption

    You can set the OPENADP_USER_ID environment variable to avoid typing it repeatedly.

SERVER DISCOVERY:
    By default, the tool fetches the server list from servers.openadp.org/api/servers.json
    If the registry is unavailable, it falls back to hardcoded servers.
    Use -servers to specify your own server list and skip discovery.

EXAMPLES:
    # Encrypt a file using discovered servers (fetches from servers.openadp.org/api/servers.json)
    openadp-encrypt --file document.txt

    # Encrypt using specific servers (skip discovery)
    openadp-encrypt --file document.txt --servers "https://server1.com,https://server2.com"

    # Use a different server registry
    openadp-encrypt --file document.txt --servers-url "https://my-registry.com"

    # Use environment variables to avoid prompts
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-encrypt --file document.txt

The encrypted file will be saved as <filename>.enc`);
}

function getHostname() {
    try {
        return os.hostname();
    } catch (error) {
        return "unknown";
    }
}

function writeUint32LE(buffer, offset, value) {
    buffer.writeUInt32LE(value, offset);
}

async function encryptFile(inputFilename, password, userId, serverInfos, serversUrl) {
    const outputFilename = inputFilename + ".enc";
    
    // Generate encryption key using OpenADP with full distributed protocol
    console.log("🔄 Generating encryption key using OpenADP servers...");
    const result = await generateEncryptionKey(inputFilename, password, userId, 10, 0, serverInfos);
    
    if (result.error) {
        throw new Error(`failed to generate encryption key: ${result.error}`);
    }
    
    // Extract information from the result
    const encKey = result.encryptionKey;
    const authCodes = result.authCodes;
    const actualServerUrls = result.serverUrls;
    const threshold = result.threshold;
    
    console.log(`🔑 Generated authentication codes for ${Object.keys(authCodes.serverAuthCodes).length} servers`);
    console.log(`🔑 Key generated successfully (UID=${userId}, DID=${getHostname()}, BID=file://${path.basename(inputFilename)})`);
    
    // Show which servers were actually used for key generation
    if (actualServerUrls.length > 0 && actualServerUrls.length !== serverInfos.length) {
        console.log(`📋 Servers actually used for key generation (${actualServerUrls.length}):`);
        for (let i = 0; i < actualServerUrls.length; i++) {
            console.log(`   ${i + 1}. ${actualServerUrls[i]}`);
        }
    }
    
    // Read input file
    let plaintext;
    try {
        plaintext = fs.readFileSync(inputFilename);
    } catch (error) {
        throw new Error(`failed to read input file: ${error.message}`);
    }
    
    // Generate random nonce
    const nonce = crypto.randomBytes(NONCE_SIZE);
    
    // Create metadata using the actual results from keygen
    const metadata = new Metadata(
        actualServerUrls,
        threshold,
        "1.0",
        authCodes.baseAuthCode,
        userId
    );
    
    const metadataJSON = Buffer.from(JSON.stringify(metadata.toDict()), 'utf8');
    
    // Encrypt the file using metadata as additional authenticated data  
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, nonce);
    cipher.setAAD(metadataJSON); // Use metadata as AAD, matching Go/Python
    
    let ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Combine ciphertext and auth tag for compatibility with Go's GCM implementation
    const encryptedData = Buffer.concat([ciphertext, authTag]);
    
    // Write encrypted file: [metadata_length][metadata][nonce][encrypted_data]
    try {
        const fd = fs.openSync(outputFilename, 'w');
        
        // Write metadata length (4 bytes, little endian)
        const metadataLengthBuffer = Buffer.alloc(4);
        writeUint32LE(metadataLengthBuffer, 0, metadataJSON.length);
        fs.writeSync(fd, metadataLengthBuffer);
        
        // Write metadata
        fs.writeSync(fd, metadataJSON);
        
        // Write nonce
        fs.writeSync(fd, nonce);
        
        // Write encrypted data
        fs.writeSync(fd, encryptedData);
        
        fs.closeSync(fd);
    } catch (error) {
        throw new Error(`failed to create output file: ${error.message}`);
    }
    
    console.log(`📁 Input:  ${inputFilename} (${plaintext.length} bytes)`);
    console.log(`📁 Output: ${outputFilename} (${4 + metadataJSON.length + NONCE_SIZE + encryptedData.length} bytes)`);
    console.log(`🔐 Encryption: AES-GCM`);
    console.log(`🌐 Servers: ${actualServerUrls.length} servers used`);
    console.log(`🎯 Threshold: ${threshold}-of-${actualServerUrls.length} recovery`);
    
    // Show final server list stored in metadata
    console.log(`📋 Servers stored in encrypted file metadata:`);
    for (let i = 0; i < actualServerUrls.length; i++) {
        console.log(`   ${i + 1}. ${actualServerUrls[i]}`);
    }
}

async function main() {
    const program = new Command();
    
    program
        .name('openadp-encrypt')
        .description('OpenADP File Encryption Tool')
        .version(VERSION);
    
    program
        .option('--file <path>', 'File to encrypt (required)')
        .option('--password <password>', 'Password for key derivation (will prompt if not provided)')
        .option('--user-id <id>', 'User ID for secret ownership (will prompt if not provided)')
        .option('--servers <urls>', 'Comma-separated list of server URLs (optional)')
        .option('--servers-url <url>', 'URL to scrape for server list', 'https://servers.openadp.org/api/servers.json')
        .allowUnknownOption()
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
    
    // Get user ID (priority: flag > environment > prompt)
    let userIdStr = "";
    if (options.userId) {
        userIdStr = options.userId;
        console.log("⚠️  Warning: User ID provided via command line (visible in process list)");
    } else if (process.env.OPENADP_USER_ID) {
        userIdStr = process.env.OPENADP_USER_ID;
        console.log("Using user ID from environment variable");
    } else {
        // TODO: Implement user input prompt for Node.js
        console.log("Error: User ID required. Use --user-id flag or OPENADP_USER_ID environment variable");
        process.exit(1);
    }
    
    // Validate user ID
    userIdStr = userIdStr.trim();
    if (userIdStr.length < 3) {
        console.log("Error: User ID must be at least 3 characters long");
        process.exit(1);
    }
    if (userIdStr.length > 64) {
        console.log("Error: User ID must be at most 64 characters long");
        process.exit(1);
    }
    
    // Get server list
    let serverInfos = [];
    if (options.servers) {
        console.log("📋 Using manually specified servers...");
        const serverUrls = options.servers.split(',').map(url => url.trim());
        console.log(`   Servers specified: ${serverUrls.length}`);
        for (let i = 0; i < serverUrls.length; i++) {
            console.log(`   ${i + 1}. ${serverUrls[i]}`);
        }
        
        // Get public keys directly from each server via GetServerInfo
        console.log("   🔍 Querying servers for public keys...");
        serverInfos = [];
        for (const url of serverUrls) {
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
    } else {
        console.log(`🌐 Discovering servers from registry: ${options.serversUrl}`);
        
        // Try to get full server information including public keys
        try {
            serverInfos = await getServers(options.serversUrl);
            if (!serverInfos || serverInfos.length === 0) {
                throw new Error("No servers returned from registry");
            }
            console.log(`   ✅ Successfully fetched ${serverInfos.length} servers from registry`);
        } catch (error) {
            console.log(`   ⚠️  Failed to fetch from registry: ${error.message}`);
            console.log("   🔄 Falling back to hardcoded servers...");
            serverInfos = getFallbackServerInfo();
            console.log(`   Fallback servers: ${serverInfos.length}`);
        }
        
        console.log("   📋 Server list with public keys:");
        for (let i = 0; i < serverInfos.length; i++) {
            const server = serverInfos[i];
            const keyStatus = server.publicKey ? "🔐 Public key available" : "❌ No public key";
            console.log(`      ${i + 1}. ${server.url} [${server.country}] - ${keyStatus}`);
        }
    }
    
    if (serverInfos.length === 0) {
        console.log("❌ Error: No servers available");
        process.exit(1);
    }
    
    // Encrypt the file
    try {
        await encryptFile(options.file, passwordStr, userIdStr, serverInfos, options.serversUrl);
        console.log("✅ File encrypted successfully!");
    } catch (error) {
        console.log(`❌ Encryption failed: ${error.message}`);
        process.exit(1);
    }
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
}); 
