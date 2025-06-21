/**
 * OpenADP Client Implementation
 * 
 * This module provides client implementations for OpenADP:
 * - Basic JSON-RPC client
 * - Noise-NK encrypted client
 * - Multi-server client with failover
 * - Server discovery functions
 */

import crypto from 'crypto';
import { Point2D, Point4D, G, hkdf, generateAuthCodes, mod, modPow } from './crypto.js';

// Error codes matching the Go implementation
const ERROR_CODES = {
    INVALID_REQUEST: -32600,
    METHOD_NOT_FOUND: -32601,
    INVALID_PARAMS: -32602,
    INTERNAL_ERROR: -32603,
    PARSE_ERROR: -32700,
    SERVER_ERROR: -32000,
    AUTHENTICATION_FAILED: -32001,
    INSUFFICIENT_SHARES: -32002,
    INVALID_SHARE: -32003,
    SECRET_NOT_FOUND: -32004,
    SERVER_UNAVAILABLE: -32005
};

/**
 * Basic OpenADP JSON-RPC client
 */
class OpenADPClient {
    constructor(serverUrl, timeout = 30000) {
        this.serverUrl = serverUrl;
        this.timeout = timeout;
        this.requestId = 0;
    }

    /**
     * Make a JSON-RPC 2.0 request
     */
    async request(method, params = []) {
        const requestId = ++this.requestId;
        const request = {
            jsonrpc: '2.0',
            method: method,
            params: params,
            id: requestId
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(this.serverUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(request),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();

            if (result.error) {
                const error = new Error(result.error.message || 'Unknown error');
                error.code = result.error.code;
                error.data = result.error.data;
                throw error;
            }

            return result.result;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }

    /**
     * Register a secret with the server
     */
    async registerSecret(secretId, share, authCode, metadata = null) {
        const params = [secretId, Array.from(share), Array.from(authCode)];
        if (metadata !== null) {
            params.push(metadata);
        }
        return await this.request('RegisterSecret', params);
    }

    /**
     * Recover a secret from the server
     */
    async recoverSecret(secretId, authCode) {
        const params = [secretId, Array.from(authCode)];
        const result = await this.request('RecoverSecret', params);
        return new Uint8Array(result);
    }

    /**
     * List backups on the server
     */
    async listBackups(authCode) {
        const params = [Array.from(authCode)];
        return await this.request('ListBackups', params);
    }

    /**
     * Get server status
     */
    async getStatus() {
        return await this.request('GetStatus', []);
    }

    /**
     * Get server public key
     */
    async getPublicKey() {
        const result = await this.request('GetPublicKey', []);
        return new Uint8Array(result);
    }
}

/**
 * Noise-NK protocol implementation
 */
class NoiseNK {
    constructor() {
        this.reset();
    }

    reset() {
        this.state = 'initial';
        this.localPrivateKey = null;
        this.localPublicKey = null;
        this.remotePublicKey = null;
        this.ephemeralPrivateKey = null;
        this.ephemeralPublicKey = null;
        this.sendKey = null;
        this.receiveKey = null;
        this.sendNonce = 0;
        this.receiveNonce = 0;
    }

    /**
     * Initialize handshake with remote public key
     */
    initialize(remotePublicKey) {
        this.remotePublicKey = new Uint8Array(remotePublicKey);
        
        // Generate ephemeral keypair
        this.ephemeralPrivateKey = crypto.randomBytes(32);
        const ephemeralScalar = this.bytesToScalar(this.ephemeralPrivateKey);
        this.ephemeralPublicKey = G.multiply(ephemeralScalar).toAffine().compress();
        
        this.state = 'initialized';
    }

    /**
     * Create handshake message
     */
    createHandshakeMessage() {
        if (this.state !== 'initialized') {
            throw new Error('Handshake not initialized');
        }

        // Noise-NK pattern: -> e, es
        const message = new Uint8Array(this.ephemeralPublicKey);
        
        // Perform DH: e * rs (ephemeral * remote static)
        const remotePoint = Point2D.decompress(this.remotePublicKey);
        const ephemeralScalar = this.bytesToScalar(this.ephemeralPrivateKey);
        const sharedSecret = remotePoint.toExtended().multiply(ephemeralScalar).toAffine().compress();
        
        // Derive keys using HKDF
        const keyMaterial = hkdf(sharedSecret, null, Buffer.from('NoiseNK'), 64);
        this.sendKey = keyMaterial.slice(0, 32);
        this.receiveKey = keyMaterial.slice(32, 64);
        
        this.state = 'handshake_sent';
        return message;
    }

    /**
     * Process handshake response
     */
    processHandshakeResponse(response) {
        if (this.state !== 'handshake_sent') {
            throw new Error('Invalid handshake state');
        }

        // In Noise-NK, the responder sends back their ephemeral key
        if (response.length !== 32) {
            throw new Error('Invalid handshake response length');
        }

        this.state = 'established';
        return true;
    }

    /**
     * Encrypt message
     */
    encrypt(plaintext) {
        if (this.state !== 'established') {
            throw new Error('Handshake not established');
        }

        const nonce = Buffer.alloc(12);
        nonce.writeUInt32LE(this.sendNonce, 0);
        this.sendNonce++;

        // Use HKDF to derive per-message key
        const messageKey = hkdf(this.sendKey, nonce, Buffer.from('encrypt'), 32);
        
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', messageKey, iv);
        cipher.setAAD(Buffer.alloc(0)); // No additional data
        
        let encrypted = cipher.update(plaintext);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const tag = cipher.getAuthTag();

        return Buffer.concat([iv, tag, encrypted]);
    }

    /**
     * Decrypt message
     */
    decrypt(ciphertext) {
        if (this.state !== 'established') {
            throw new Error('Handshake not established');
        }

        if (ciphertext.length < 28) { // 12 IV + 16 tag minimum
            throw new Error('Ciphertext too short');
        }

        const iv = ciphertext.slice(0, 12);
        const tag = ciphertext.slice(12, 28);
        const encrypted = ciphertext.slice(28);

        const nonce = Buffer.alloc(12);
        nonce.writeUInt32LE(this.receiveNonce, 0);
        this.receiveNonce++;

        // Use HKDF to derive per-message key
        const messageKey = hkdf(this.receiveKey, nonce, Buffer.from('decrypt'), 32);

        const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey, iv);
        decipher.setAAD(Buffer.alloc(0)); // No additional data
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted;
    }

    bytesToScalar(bytes) {
        let result = 0n;
        for (let i = bytes.length - 1; i >= 0; i--) {
            result = (result << 8n) + BigInt(bytes[i]);
        }
        // Clamp for Ed25519 scalar
        result &= (1n << 254n) - 1n;
        result |= 1n << 254n;
        return result;
    }
}

/**
 * Encrypted OpenADP client using Noise-NK protocol
 */
class EncryptedOpenADPClient {
    constructor(serverUrl, serverPublicKey, timeout = 30000) {
        this.serverUrl = serverUrl;
        this.serverPublicKey = new Uint8Array(serverPublicKey);
        this.timeout = timeout;
        this.noise = new NoiseNK();
        this.requestId = 0;
        this.established = false;
    }

    /**
     * Establish encrypted connection
     */
    async connect() {
        if (this.established) {
            return;
        }

        // Initialize Noise-NK handshake
        this.noise.initialize(this.serverPublicKey);
        const handshakeMessage = this.noise.createHandshakeMessage();

        // Send handshake to server
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(`${this.serverUrl}/handshake`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/octet-stream',
                },
                body: handshakeMessage,
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`Handshake failed: HTTP ${response.status}`);
            }

            const responseData = new Uint8Array(await response.arrayBuffer());
            this.noise.processHandshakeResponse(responseData);
            this.established = true;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Handshake timeout');
            }
            throw error;
        }
    }

    /**
     * Make encrypted JSON-RPC request
     */
    async request(method, params = []) {
        await this.connect();

        const requestId = ++this.requestId;
        const request = {
            jsonrpc: '2.0',
            method: method,
            params: params,
            id: requestId
        };

        const requestData = Buffer.from(JSON.stringify(request), 'utf8');
        const encryptedRequest = this.noise.encrypt(requestData);

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(`${this.serverUrl}/rpc`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/octet-stream',
                },
                body: encryptedRequest,
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const encryptedResponse = new Uint8Array(await response.arrayBuffer());
            const decryptedResponse = this.noise.decrypt(encryptedResponse);
            const result = JSON.parse(decryptedResponse.toString('utf8'));

            if (result.error) {
                const error = new Error(result.error.message || 'Unknown error');
                error.code = result.error.code;
                error.data = result.error.data;
                throw error;
            }

            return result.result;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }

    /**
     * Register a secret with the server
     */
    async registerSecret(secretId, share, authCode, metadata = null) {
        const params = [secretId, Array.from(share), Array.from(authCode)];
        if (metadata !== null) {
            params.push(metadata);
        }
        return await this.request('RegisterSecret', params);
    }

    /**
     * Recover a secret from the server
     */
    async recoverSecret(secretId, authCode) {
        const params = [secretId, Array.from(authCode)];
        const result = await this.request('RecoverSecret', params);
        return new Uint8Array(result);
    }

    /**
     * List backups on the server
     */
    async listBackups(authCode) {
        const params = [Array.from(authCode)];
        return await this.request('ListBackups', params);
    }

    /**
     * Get server status
     */
    async getStatus() {
        return await this.request('GetStatus', []);
    }

    /**
     * Get server public key
     */
    async getPublicKey() {
        const result = await this.request('GetPublicKey', []);
        return new Uint8Array(result);
    }

    /**
     * Reset connection
     */
    disconnect() {
        this.noise.reset();
        this.established = false;
    }
}

/**
 * Multi-server client with failover support
 */
class MultiServerClient {
    constructor(servers = [], timeout = 30000) {
        this.servers = servers.map(server => ({
            url: server.url,
            publicKey: new Uint8Array(server.publicKey),
            client: new EncryptedOpenADPClient(server.url, server.publicKey, timeout)
        }));
        this.timeout = timeout;
    }

    /**
     * Add a server to the client
     */
    addServer(url, publicKey) {
        const server = {
            url: url,
            publicKey: new Uint8Array(publicKey),
            client: new EncryptedOpenADPClient(url, publicKey, this.timeout)
        };
        this.servers.push(server);
    }

    /**
     * Remove a server from the client
     */
    removeServer(url) {
        this.servers = this.servers.filter(server => server.url !== url);
    }

    /**
     * Execute operation on all servers concurrently
     */
    async executeOnAll(operation, ...args) {
        const promises = this.servers.map(async (server) => {
            try {
                const result = await server.client[operation](...args);
                return { server: server.url, success: true, result: result };
            } catch (error) {
                return { server: server.url, success: false, error: error.message };
            }
        });

        return await Promise.all(promises);
    }

    /**
     * Execute operation on servers with threshold requirement
     */
    async executeWithThreshold(operation, threshold, ...args) {
        const results = await this.executeOnAll(operation, ...args);
        const successful = results.filter(r => r.success);
        
        if (successful.length < threshold) {
            const errors = results.filter(r => !r.success).map(r => r.error);
            throw new Error(`Insufficient successful responses: ${successful.length}/${threshold}. Errors: ${errors.join(', ')}`);
        }

        return successful;
    }

    /**
     * Register secret on multiple servers
     */
    async registerSecret(secretId, shares, authCodes, metadata = null, threshold = null) {
        if (shares.length !== this.servers.length) {
            throw new Error('Number of shares must match number of servers');
        }

        const promises = this.servers.map(async (server, index) => {
            try {
                const authCode = authCodes[server.url] || authCodes[index];
                const result = await server.client.registerSecret(secretId, shares[index], authCode, metadata);
                return { server: server.url, success: true, result: result };
            } catch (error) {
                return { server: server.url, success: false, error: error.message };
            }
        });

        const results = await Promise.all(promises);
        const successful = results.filter(r => r.success);
        const requiredThreshold = threshold || Math.ceil(this.servers.length / 2);

        if (successful.length < requiredThreshold) {
            const errors = results.filter(r => !r.success).map(r => r.error);
            throw new Error(`Failed to register on sufficient servers: ${successful.length}/${requiredThreshold}. Errors: ${errors.join(', ')}`);
        }

        return successful;
    }

    /**
     * Recover secret from multiple servers
     */
    async recoverSecret(secretId, authCodes, threshold) {
        const promises = this.servers.map(async (server) => {
            try {
                const authCode = authCodes[server.url];
                if (!authCode) {
                    throw new Error('No auth code for server');
                }
                const share = await server.client.recoverSecret(secretId, authCode);
                return { server: server.url, success: true, share: share };
            } catch (error) {
                return { server: server.url, success: false, error: error.message };
            }
        });

        const results = await Promise.all(promises);
        const successful = results.filter(r => r.success);

        if (successful.length < threshold) {
            const errors = results.filter(r => !r.success).map(r => r.error);
            throw new Error(`Insufficient shares recovered: ${successful.length}/${threshold}. Errors: ${errors.join(', ')}`);
        }

        return successful.slice(0, threshold).map(r => r.share);
    }

    /**
     * List backups from all servers
     */
    async listBackups(authCodes) {
        const results = await this.executeOnAll('listBackups', authCodes);
        return results;
    }

    /**
     * Get status from all servers
     */
    async getStatus() {
        const results = await this.executeOnAll('getStatus');
        return results;
    }

    /**
     * Test connectivity to all servers
     */
    async testConnectivity() {
        const promises = this.servers.map(async (server) => {
            try {
                await server.client.getStatus();
                return { server: server.url, success: true, latency: Date.now() };
            } catch (error) {
                return { server: server.url, success: false, error: error.message };
            }
        });

        return await Promise.all(promises);
    }
}

/**
 * Server discovery functions
 */
async function discoverServers(urls, timeout = 5000) {
    const promises = urls.map(async (url) => {
        try {
            const client = new OpenADPClient(url, timeout);
            const status = await client.getStatus();
            const publicKey = await client.getPublicKey();
            
            return {
                url: url,
                publicKey: publicKey,
                status: status,
                available: true
            };
        } catch (error) {
            return {
                url: url,
                available: false,
                error: error.message
            };
        }
    });

    return await Promise.all(promises);
}

/**
 * Scrape servers from a discovery endpoint
 */
async function scrapeServers(discoveryUrl, timeout = 5000) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(discoveryUrl, {
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const servers = await response.json();
        return servers.map(server => ({
            url: server.url,
            publicKey: new Uint8Array(server.publicKey),
            metadata: server.metadata || {}
        }));
    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Discovery timeout');
        }
        throw error;
    }
}

export {
    OpenADPClient,
    EncryptedOpenADPClient,
    MultiServerClient,
    NoiseNK,
    ERROR_CODES,
    discoverServers,
    scrapeServers
}; 