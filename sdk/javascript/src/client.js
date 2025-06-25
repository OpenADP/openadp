/**
 * OpenADP JavaScript Client Implementation
 * 
 * This module provides JavaScript client implementations for OpenADP servers,
 * matching the Python functionality exactly:
 * 
 * - OpenADPClient: Basic JSON-RPC client (no encryption)
 * - EncryptedOpenADPClient: JSON-RPC client with Noise-NK encryption
 * - MultiServerClient: High-level client managing multiple servers
 */

import { NoiseNK, generateStaticKeyPair } from './noise-nk.js';

// Error codes matching Python implementation
export const ErrorCode = {
    NETWORK_FAILURE: 1001,
    AUTHENTICATION_FAILED: 1002,
    INVALID_REQUEST: 1003,
    SERVER_ERROR: 1004,
    ENCRYPTION_FAILED: 1005,
    NO_LIVE_SERVERS: 1006,
    INVALID_RESPONSE: 1007
};

export const ServerSelectionStrategy = {
    FIRST_AVAILABLE: 0,
    ROUND_ROBIN: 1,
    RANDOM: 2,
    LOWEST_LATENCY: 3
};

/**
 * Server information from registry or configuration
 */
export class ServerInfo {
    constructor(url, publicKey = "", country = "Unknown", remainingGuesses = -1) {
        this.url = url;
        this.publicKey = publicKey;
        this.country = country || "Unknown";
        this.remainingGuesses = remainingGuesses; // -1 means unknown, >=0 means known remaining guesses
    }
}

/**
 * Standardized request for RegisterSecret operation
 */
export class RegisterSecretRequest {
    constructor(authCode, uid, did, bid, version, x, y, maxGuesses, expiration, encrypted = false, authData = null) {
        this.authCode = authCode;
        this.uid = uid;
        this.did = did;
        this.bid = bid;
        this.version = version;
        this.x = x;
        this.y = y; // Base64 encoded point
        this.maxGuesses = maxGuesses;
        this.expiration = expiration;
        this.encrypted = encrypted;
        this.authData = authData;
    }
}

/**
 * Standardized response for RegisterSecret operation
 */
export class RegisterSecretResponse {
    constructor(success, message = "") {
        this.success = success;
        this.message = message;
    }
}

/**
 * Standardized request for RecoverSecret operation
 */
export class RecoverSecretRequest {
    constructor(authCode, uid, did, bid, b, guessNum, encrypted = false, authData = null) {
        this.authCode = authCode;
        this.uid = uid;
        this.did = did;
        this.bid = bid;
        this.b = b; // Base64 encoded point
        this.guessNum = guessNum;
        this.encrypted = encrypted;
        this.authData = authData;
    }
}

/**
 * Standardized response for RecoverSecret operation
 */
export class RecoverSecretResponse {
    constructor(version, x, siB, numGuesses, maxGuesses, expiration) {
        this.version = version;
        this.x = x;
        this.siB = siB; // Base64 encoded point
        this.numGuesses = numGuesses;
        this.maxGuesses = maxGuesses;
        this.expiration = expiration;
    }
}

/**
 * Standardized request for ListBackups operation
 */
export class ListBackupsRequest {
    constructor(uid, authCode = "", encrypted = false, authData = null) {
        this.uid = uid;
        this.authCode = authCode;
        this.encrypted = encrypted;
        this.authData = authData;
    }
}

/**
 * Information about a backup
 */
export class BackupInfo {
    constructor(uid, did, bid, version, numGuesses, maxGuesses, expiration) {
        this.uid = uid;
        this.did = did;
        this.bid = bid;
        this.version = version;
        this.numGuesses = numGuesses;
        this.maxGuesses = maxGuesses;
        this.expiration = expiration;
    }
}

/**
 * Standardized response for ListBackups operation
 */
export class ListBackupsResponse {
    constructor(backups) {
        this.backups = backups || [];
    }
}

/**
 * Standardized response for GetServerInfo operation
 */
export class ServerInfoResponse {
    constructor(serverVersion, noiseNkPublicKey = "", supportedMethods = [], maxRequestSize = 0, rateLimits = {}) {
        this.serverVersion = serverVersion;
        this.noiseNkPublicKey = noiseNkPublicKey;
        this.supportedMethods = supportedMethods;
        this.maxRequestSize = maxRequestSize;
        this.rateLimits = rateLimits;
    }
}

/**
 * OpenADP-specific error with error codes
 */
export class OpenADPError extends Error {
    constructor(code, message, details = null) {
        super();
        this.code = code;
        this.message = message;
        this.details = details;
        this.name = 'OpenADPError';
    }

    toString() {
        if (this.details) {
            return `OpenADP Error ${this.code}: ${this.message} (${this.details})`;
        }
        return `OpenADP Error ${this.code}: ${this.message}`;
    }
}

/**
 * JSON-RPC 2.0 error structure
 */
export class JSONRPCError {
    constructor(code, message, data = null) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    toDict() {
        const result = {
            code: this.code,
            message: this.message
        };
        
        if (this.data !== null) {
            result.data = this.data;
        }
        
        return result;
    }
}

/**
 * JSON-RPC 2.0 request structure
 */
export class JSONRPCRequest {
    constructor(method, params = null, requestId = 1) {
        this.jsonrpc = "2.0";
        this.method = method;
        this.params = params;
        this.id = requestId;
    }

    toDict() {
        const result = {
            jsonrpc: this.jsonrpc,
            method: this.method,
            id: this.id
        };
        if (this.params !== null) {
            result.params = this.params;
        }
        return result;
    }
}

/**
 * JSON-RPC 2.0 response structure
 */
export class JSONRPCResponse {
    constructor(result = null, error = null, requestId = 1) {
        this.jsonrpc = "2.0";
        this.result = result;
        this.error = error;
        this.id = requestId;
    }

    toDict() {
        const result = {
            jsonrpc: this.jsonrpc,
            id: this.id
        };
        
        if (this.result !== null) {
            result.result = this.result;
        }
        
        if (this.error !== null) {
            result.error = this.error;
        }
        
        return result;
    }

    static fromDict(data) {
        const response = new JSONRPCResponse();
        response.jsonrpc = data.jsonrpc || "2.0";
        response.result = data.result !== undefined ? data.result : null;
        response.id = data.id !== undefined ? data.id : null;

        // Handle error field - can be string or structured
        if ("error" in data && data.error !== null) {
            const errorData = data.error;
            if (typeof errorData === 'string') {
                // Simple string error
                response.error = new JSONRPCError(-32603, errorData);
            } else if (typeof errorData === 'object') {
                // Structured error
                response.error = new JSONRPCError(
                    errorData.code || -32603,
                    errorData.message || "Unknown error",
                    errorData.data
                );
            }
        }

        return response;
    }
}

/**
 * Basic OpenADP client with JSON-RPC support (no encryption)
 */
export class OpenADPClient {
    constructor(url, timeout = 30000) {
        this.url = url;
        this.timeout = timeout;
        this.requestId = 1;
    }

    async _makeRequest(method, params = null) {
        const request = new JSONRPCRequest(method, params, this.requestId++);

        try {
            const response = await fetch(this.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(request.toDict()),
                signal: AbortSignal.timeout(this.timeout)
            });

            if (!response.ok) {
                throw new OpenADPError(
                    ErrorCode.NETWORK_FAILURE,
                    `HTTP error: ${response.status} ${response.statusText}`,
                    `URL: ${this.url}`
                );
            }

            const responseData = await response.json();
            const jsonRpcResponse = JSONRPCResponse.fromDict(responseData);

            if (jsonRpcResponse.error) {
                throw new OpenADPError(
                    ErrorCode.SERVER_ERROR,
                    jsonRpcResponse.error.message,
                    `Server: ${this.url}, Code: ${jsonRpcResponse.error.code}`
                );
            }

            return jsonRpcResponse.result;

        } catch (error) {
            if (error instanceof OpenADPError) {
                throw error;
            }

            if (error.name === 'AbortError') {
                throw new OpenADPError(
                    ErrorCode.NETWORK_FAILURE,
                    'Request timeout',
                    `URL: ${this.url}, Timeout: ${this.timeout}ms`
                );
            }

            throw new OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                `Network error: ${error.message}`,
                `URL: ${this.url}`
            );
        }
    }

    async listBackups(uid) {
        return await this._makeRequest("ListBackups", [uid]);
    }

    async echo(message) {
        return await this._makeRequest("Echo", [message]);
    }

    async ping() {
        try {
            const result = await this.echo("ping");
            if (result !== "ping") {
                throw new OpenADPError(
                    ErrorCode.INVALID_RESPONSE,
                    "Invalid ping response",
                    `Expected: ping, Got: ${result}`
                );
            }
        } catch (error) {
            throw new OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                "Ping failed",
                error.message
            );
        }
    }

    async getServerInfo() {
        return await this._makeRequest("GetServerInfo", null);
    }

    async registerSecretStandardized(request) {
        try {
            const result = await this._makeRequest("RegisterSecret", [
                request.authCode, request.uid, request.did, request.bid,
                request.version, request.x, request.y, request.maxGuesses, request.expiration
            ]);
            return new RegisterSecretResponse(result);
        } catch (error) {
            return new RegisterSecretResponse(false, error.message);
        }
    }

    async recoverSecretStandardized(request) {
        const result = await this._makeRequest("RecoverSecret", [
            request.authCode, request.uid, request.did, request.bid, request.b, request.guessNum
        ]);
        return new RecoverSecretResponse(
            result.version, result.x, result.si_b, 
            result.num_guesses, result.max_guesses, result.expiration
        );
    }

    async listBackupsStandardized(request) {
        const result = await this.listBackups(request.uid);
        const backups = result.map(backup => new BackupInfo(
            backup.uid, backup.did, backup.bid, backup.version,
            backup.num_guesses, backup.max_guesses, backup.expiration
        ));
        return new ListBackupsResponse(backups);
    }

    async getServerInfoStandardized() {
        const result = await this.getServerInfo();
        return new ServerInfoResponse(
            result.version || "unknown",
            result.noise_nk_public_key || "",
            result.capabilities || [],
            result.max_request_size || 0,
            result.rate_limits || {}
        );
    }

    async testConnection() {
        await this.ping();
    }

    getServerUrl() {
        return this.url;
    }

    supportsEncryption() {
        return false;
    }
}

/**
 * Parse server public key from base64 or ed25519: format
 */
export function parseServerPublicKey(keyB64) {
    if (!keyB64) {
        return null;
    }

    try {
        if (keyB64.startsWith("ed25519:")) {
            // Remove ed25519: prefix and decode
            const keyData = keyB64.substring(8);
            return new Uint8Array(atob(keyData).split('').map(c => c.charCodeAt(0)));
        } else {
            // Assume it's already base64
            return new Uint8Array(atob(keyB64).split('').map(c => c.charCodeAt(0)));
        }
    } catch (error) {
        throw new Error(`Invalid public key format: ${error.message}`);
    }
}

/**
 * OpenADP client with Noise-NK encryption support
 */
export class EncryptedOpenADPClient {
    constructor(url, serverPublicKey = null, timeout = 30000) {
        this.url = url;
        this.serverPublicKey = serverPublicKey;
        this.timeout = timeout;
        this.requestId = 1;
        this.noise = null;
        this.handshakeComplete = false;
        this.sessionID = null;
    }

    hasPublicKey() {
        return this.serverPublicKey !== null;
    }

    async _makeRequest(method, params = null, encrypted = false, authData = null) {
        if (encrypted && this.serverPublicKey) {
            return await this._makeEncryptedRequest(method, params, authData);
        } else {
            return await this._makeUnencryptedRequest(method, params);
        }
    }

    async _makeUnencryptedRequest(method, params = null) {
        const request = new JSONRPCRequest(method, params, this.requestId++);

        try {
            const response = await fetch(this.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(request.toDict()),
                signal: AbortSignal.timeout(this.timeout)
            });

            if (!response.ok) {
                throw new OpenADPError(
                    ErrorCode.NETWORK_FAILURE,
                    `HTTP error: ${response.status} ${response.statusText}`,
                    `URL: ${this.url}`
                );
            }

            const responseData = await response.json();
            const jsonRpcResponse = JSONRPCResponse.fromDict(responseData);

            if (jsonRpcResponse.error) {
                throw new OpenADPError(
                    ErrorCode.SERVER_ERROR,
                    jsonRpcResponse.error.message,
                    `Server: ${this.url}, Code: ${jsonRpcResponse.error.code}`
                );
            }

            return jsonRpcResponse.result;

        } catch (error) {
            if (error instanceof OpenADPError) {
                throw error;
            }

            if (error.name === 'AbortError') {
                throw new OpenADPError(
                    ErrorCode.NETWORK_FAILURE,
                    'Request timeout',
                    `URL: ${this.url}, Timeout: ${this.timeout}ms`
                );
            }

            throw new OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                `Network error: ${error.message}`,
                `URL: ${this.url}`
            );
        }
    }

    async _makeEncryptedRequest(method, params = null, authData = null) {
        if (!this.serverPublicKey) {
            throw new OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                "No server public key available for encryption",
                `URL: ${this.url}`
            );
        }

        try {
            // Initialize Noise-NK if not already done
            if (!this.noise || !this.handshakeComplete) {
                await this._performHandshake();
            }

            // Create JSON-RPC request for the actual method call
            const methodCall = {
                jsonrpc: "2.0",
                method: method,
                params: params,
                id: this.requestId++
            };

            // Add auth data if provided
            if (authData) {
                methodCall.auth = authData;
            }

            // Serialize and encrypt the method call
            const methodCallJson = JSON.stringify(methodCall);
            const methodCallBytes = new TextEncoder().encode(methodCallJson);
            const encryptedCall = this.noise.encrypt(methodCallBytes);

            // Send encrypted_call request (Round 2)
            const encryptedRequest = {
                jsonrpc: "2.0",
                method: "encrypted_call",
                params: [{
                    session: this.sessionID,
                    data: btoa(String.fromCharCode(...encryptedCall))
                }],
                id: this.requestId++
            };

            const response = await fetch(this.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(encryptedRequest),
                signal: AbortSignal.timeout(this.timeout)
            });

            if (!response.ok) {
                throw new OpenADPError(
                    ErrorCode.NETWORK_FAILURE,
                    `HTTP error: ${response.status} ${response.statusText}`,
                    `URL: ${this.url}`
                );
            }

            const encryptedResponse = await response.json();

            if (encryptedResponse.error) {
                throw new OpenADPError(
                    ErrorCode.SERVER_ERROR,
                    `Encrypted call JSON-RPC error: ${encryptedResponse.error.message}`,
                    `Code: ${encryptedResponse.error.code}`
                );
            }

            // Decrypt the response
            const encryptedDataB64 = encryptedResponse.result.data;
            const encryptedDataBytes = new Uint8Array(atob(encryptedDataB64).split('').map(c => c.charCodeAt(0)));
            const decryptedBytes = this.noise.decrypt(encryptedDataBytes);
            const decryptedJson = new TextDecoder().decode(decryptedBytes);
            const responseData = JSON.parse(decryptedJson);

            const jsonRpcResponse = JSONRPCResponse.fromDict(responseData);

            if (jsonRpcResponse.error) {
                throw new OpenADPError(
                    ErrorCode.SERVER_ERROR,
                    jsonRpcResponse.error.message,
                    `Server: ${this.url}, Code: ${jsonRpcResponse.error.code}`
                );
            }

            return jsonRpcResponse.result;

        } catch (error) {
            if (error instanceof OpenADPError) {
                throw error;
            }

            if (error.name === 'AbortError') {
                throw new OpenADPError(
                    ErrorCode.NETWORK_FAILURE,
                    'Request timeout',
                    `URL: ${this.url}, Timeout: ${this.timeout}ms`
                );
            }

            throw new OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                `Encryption error: ${error.message}`,
                `URL: ${this.url}`
            );
        }
    }

    async _performHandshake() {
        // Step 1: Generate session ID
        const sessionID = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        // Step 2: Initialize Noise-NK as initiator
        this.noise = new NoiseNK();
        this.noise.initializeInitiator(this.serverPublicKey);

        // Step 3: Create first handshake message
        const handshakeMsg1 = this.noise.writeMessage(new Uint8Array(0)); // Empty payload

        // Step 4: Send noise_handshake request (Round 1)
        const handshakeRequest = {
            jsonrpc: "2.0",
            method: "noise_handshake",
            params: [{
                session: sessionID,
                message: btoa(String.fromCharCode(...handshakeMsg1))
            }],
            id: this.requestId++
        };

        const response1 = await fetch(this.url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(handshakeRequest),
            signal: AbortSignal.timeout(this.timeout)
        });

        if (!response1.ok) {
            throw new OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                `Handshake failed: ${response1.status} ${response1.statusText}`,
                `URL: ${this.url}`
            );
        }

        const handshakeResponse = await response1.json();
        
        if (handshakeResponse.error) {
            throw new OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                `Handshake JSON-RPC error: ${handshakeResponse.error.message}`,
                `Code: ${handshakeResponse.error.code}`
            );
        }

        // Step 5: Process server's handshake response
        const handshakeMsgB64 = handshakeResponse.result.message;
        const handshakeMsg2 = new Uint8Array(atob(handshakeMsgB64).split('').map(c => c.charCodeAt(0)));
        
        // Complete handshake
        this.noise.readMessage(handshakeMsg2);

        if (!this.noise.handshakeComplete) {
            throw new OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                "Noise-NK handshake failed to complete",
                `URL: ${this.url}`
            );
        }

        this.handshakeComplete = true;
        this.sessionID = sessionID;
    }

    async registerSecret(authCode, uid, did, bid, version, x, y, maxGuesses, expiration, encrypted = true, authData = null) {
        return await this._makeRequest("RegisterSecret", [
            authCode, uid, did, bid, version, x, y, maxGuesses, expiration
        ], encrypted, authData);
    }

    async recoverSecret(authCode, uid, did, bid, b, guessNum, encrypted = true, authData = null) {
        return await this._makeRequest("RecoverSecret", [
            authCode, uid, did, bid, b, guessNum
        ], encrypted, authData);
    }

    async listBackups(uid, encrypted = false, authData = null) {
        return await this._makeRequest("ListBackups", [uid], encrypted, authData);
    }

    async echo(message, encrypted = false) {
        return await this._makeRequest("Echo", [message], encrypted);
    }

    async ping() {
        try {
            const result = await this.echo("ping", false); // Use unencrypted ping
            if (result !== "ping") {
                throw new OpenADPError(
                    ErrorCode.INVALID_RESPONSE,
                    "Invalid ping response",
                    `Expected: ping, Got: ${result}`
                );
            }
        } catch (error) {
            throw new OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                "Ping failed",
                error.message
            );
        }
    }

    async getServerInfo() {
        return await this._makeRequest("GetServerInfo", null, false); // Always unencrypted
    }

    async registerSecretStandardized(request) {
        try {
            const result = await this.registerSecret(
                request.authCode, request.uid, request.did, request.bid,
                request.version, request.x, request.y, request.maxGuesses, 
                request.expiration, request.encrypted, request.authData
            );
            return new RegisterSecretResponse(result);
        } catch (error) {
            return new RegisterSecretResponse(false, error.message);
        }
    }

    async recoverSecretStandardized(request) {
        const result = await this.recoverSecret(
            request.authCode, request.uid, request.did, request.bid, 
            request.b, request.guessNum, request.encrypted, request.authData
        );
        return new RecoverSecretResponse(
            result.version, result.x, result.si_b, 
            result.num_guesses, result.max_guesses, result.expiration
        );
    }

    async listBackupsStandardized(request) {
        const result = await this.listBackups(request.uid, request.encrypted, request.authData);
        const backups = result.map(backup => new BackupInfo(
            backup.uid, backup.did, backup.bid, backup.version,
            backup.num_guesses, backup.max_guesses, backup.expiration
        ));
        return new ListBackupsResponse(backups);
    }

    async getServerInfoStandardized() {
        const result = await this.getServerInfo();
        return new ServerInfoResponse(
            result.version || "unknown",
            result.noise_nk_public_key || "",
            result.capabilities || [],
            result.max_request_size || 0,
            result.rate_limits || {}
        );
    }

    async testConnection() {
        await this.ping();
    }

    getServerUrl() {
        return this.url;
    }

    supportsEncryption() {
        return this.hasPublicKey();
    }
}

/**
 * Server registry response
 */
export class ServersResponse {
    constructor(servers) {
        this.servers = servers || [];
    }
}

/**
 * Get servers from registry URL
 */
export async function getServers(registryUrl = "") {
    const finalUrl = registryUrl || "https://servers.openadp.org/api/servers.json";
    
    try {
        const response = await fetch(finalUrl);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        if (Array.isArray(data)) {
            return data.map(server => new ServerInfo(
                server.url || server.URL,
                server.public_key || server.noise_nk_public_key || "",
                server.country || "",
                server.remaining_guesses || -1
            ));
        } else if (data.servers) {
            return data.servers.map(server => new ServerInfo(
                server.url || server.URL,
                server.public_key || server.noise_nk_public_key || "",
                server.country || "",
                server.remaining_guesses || -1
            ));
        }
        
        throw new Error("Invalid server registry format");
    } catch (error) {
        console.warn(`Failed to fetch servers from ${finalUrl}: ${error.message}`);
        return getFallbackServerInfo();
    }
}

/**
 * Get fallback server information
 */
export function getFallbackServerInfo() {
    return [
        new ServerInfo("http://localhost:8080", "", "Local", -1)
    ];
}

/**
 * High-level multi-server client
 */
export class MultiServerClient {
    constructor(serversUrl = "", fallbackServers = null, echoTimeout = 10000, maxWorkers = 10) {
        this.serversUrl = serversUrl || "https://servers.openadp.org/api/servers.json";
        this.fallbackServers = fallbackServers || [];
        this.echoTimeout = echoTimeout;
        this.maxWorkers = maxWorkers;
        this.liveServers = [];
        this.serverSelectionStrategy = ServerSelectionStrategy.FIRST_AVAILABLE;
        this.roundRobinIndex = 0;
    }

    static fromServerInfo(serverInfos, echoTimeout = 10000, maxWorkers = 10) {
        const client = new MultiServerClient("", [], echoTimeout, maxWorkers);
        client._initializeServersFromInfo(serverInfos);
        return client;
    }

    async _initializeServers() {
        console.log("Discovering OpenADP servers...");
        
        let serverInfos;
        try {
            serverInfos = await getServers(this.serversUrl);
            if (serverInfos.length === 0) {
                throw new Error("No servers returned from registry");
            }
            console.log(`Found ${serverInfos.length} servers from registry`);
        } catch (error) {
            console.warn(`Server discovery failed: ${error.message}`);
            console.log("Using fallback servers");
            serverInfos = this.fallbackServers.map(url => new ServerInfo(url));
        }

        this.liveServers = await this._testServersConcurrently(serverInfos);
        this._logServerStatus();
    }

    _initializeServersFromInfo(serverInfos) {
        this._testServersConcurrently(serverInfos).then(liveServers => {
            this.liveServers = liveServers;
            this._logServerStatus();
        });
    }

    async _testServersConcurrently(serverInfos) {
        const testPromises = serverInfos.map(serverInfo => this._testSingleServerWithInfo(serverInfo));
        const results = await Promise.allSettled(testPromises);
        
        return results
            .filter(result => result.status === 'fulfilled' && result.value !== null)
            .map(result => result.value);
    }

    async _testSingleServerWithInfo(serverInfo) {
        try {
            const publicKey = this._parsePublicKey(serverInfo.publicKey);
            const client = new EncryptedOpenADPClient(serverInfo.url, publicKey, this.echoTimeout);
            
            await client.ping();
            
            console.log(`✓ Server ${serverInfo.url} is live`);
            return client;
            
        } catch (error) {
            console.log(`✗ Server ${serverInfo.url} failed: ${error.message}`);
            return null;
        }
    }

    _parsePublicKey(publicKey) {
        if (!publicKey) {
            return null;
        }
        
        try {
            return parseServerPublicKey(publicKey);
        } catch (error) {
            console.warn(`Invalid public key format: ${error.message}`);
            return null;
        }
    }

    _logServerStatus() {
        console.log(`Live servers: ${this.liveServers.length}`);
        for (const [index, server] of this.liveServers.entries()) {
            const encryption = server.supportsEncryption() ? "Encrypted" : "Unencrypted";
            console.log(`  ${index + 1}. ${server.getServerUrl()} (${encryption})`);
        }
    }

    getLiveServerCount() {
        return this.liveServers.length;
    }

    getLiveServerUrls() {
        return this.liveServers.map(server => server.getServerUrl());
    }

    async refreshServers() {
        await this._initializeServers();
    }

    _selectServer() {
        if (this.liveServers.length === 0) {
            throw new OpenADPError(ErrorCode.NO_LIVE_SERVERS, "No live servers available");
        }

        switch (this.serverSelectionStrategy) {
            case ServerSelectionStrategy.ROUND_ROBIN:
                const server = this.liveServers[this.roundRobinIndex % this.liveServers.length];
                this.roundRobinIndex++;
                return server;
            
            case ServerSelectionStrategy.RANDOM:
                const randomIndex = Math.floor(Math.random() * this.liveServers.length);
                return this.liveServers[randomIndex];
            
            case ServerSelectionStrategy.FIRST_AVAILABLE:
            default:
                return this.liveServers[0];
        }
    }

    async registerSecret(uid, did, bid, version, x, y, maxGuesses, expiration, authData = null) {
        const server = this._selectServer();
        // Note: auth_code would be derived from authData in actual implementation
        const authCode = authData?.auth_code || "";
        return await server.registerSecret(authCode, uid, did, bid, version, x, y, maxGuesses, expiration, true, authData);
    }

    async recoverSecret(authCode, uid, did, bid, b, guessNum, authData = null) {
        const server = this._selectServer();
        return await server.recoverSecret(authCode, uid, did, bid, b, guessNum, true, authData);
    }

    async listBackups(uid) {
        const server = this._selectServer();
        return await server.listBackups(uid, false); // Usually unencrypted
    }

    async echo(message) {
        const server = this._selectServer();
        return await server.echo(message, false);
    }

    async ping() {
        if (this.liveServers.length === 0) {
            await this._initializeServers();
        }
        
        const server = this._selectServer();
        await server.ping();
    }

    async getServerInfo() {
        const server = this._selectServer();
        return await server.getServerInfo();
    }

    setServerSelectionStrategy(strategy) {
        this.serverSelectionStrategy = strategy;
    }

    // Standardized interface methods
    async registerSecretStandardized(request) {
        const server = this._selectServer();
        return await server.registerSecretStandardized(request);
    }

    async recoverSecretStandardized(request) {
        const server = this._selectServer();
        return await server.recoverSecretStandardized(request);
    }

    async listBackupsStandardized(request) {
        const server = this._selectServer();
        return await server.listBackupsStandardized(request);
    }

    async getServerInfoStandardized() {
        const server = this._selectServer();
        return await server.getServerInfoStandardized();
    }

    async testConnection() {
        await this.ping();
    }

    getServerUrl() {
        if (this.liveServers.length === 0) {
            return "No live servers";
        }
        return this.liveServers.map(s => s.getServerUrl()).join(", ");
    }

    supportsEncryption() {
        return this.liveServers.some(server => server.supportsEncryption());
    }
}

// Initialize servers on first use
MultiServerClient.prototype._initialized = false;

const originalMethods = ['registerSecret', 'recoverSecret', 'listBackups', 'echo', 'ping', 'getServerInfo'];
for (const method of originalMethods) {
    const originalMethod = MultiServerClient.prototype[method];
    MultiServerClient.prototype[method] = async function(...args) {
        if (!this._initialized) {
            await this._initializeServers();
            this._initialized = true;
        }
        return originalMethod.apply(this, args);
    };
} 