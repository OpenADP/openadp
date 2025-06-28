/**
 * Noise-NK Protocol Implementation
 * Pattern: Noise_NK_25519_AESGCM_SHA256
 *
 * Follows the official Noise Protocol Framework specification:
 * <- s
 * ...
 * -> e, es
 * <- e, ee
 *
 * This implementation must be compatible with existing Go servers.
 */

import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
// Use Node.js crypto for both AES-GCM and randomBytes
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import * as debug from './debug.js';

const PROTOCOL_NAME = "Noise_NK_25519_AESGCM_SHA256";
const DHLEN = 32;
const HASHLEN = 32;

/**
 * HKDF implementation as specified in Noise Protocol Framework
 */
function noiseHKDF(chainingKey, inputKeyMaterial, numOutputs) {
    // Use Noble's hkdf with the chaining key as salt
    const length = numOutputs * HASHLEN;
    const result = hkdf(sha256, inputKeyMaterial, chainingKey, new Uint8Array(), length);
    return result;
}

/**
 * Noise-NK Protocol Implementation
 */
export class NoiseNK {
    constructor() {
        this.reset();
    }

    reset() {
        // Handshake state variables
        this.h = new Uint8Array(HASHLEN);           // handshake hash
        this.ck = new Uint8Array(HASHLEN);          // chaining key
        this.k = null;                              // symmetric key (32 bytes when set)
        this.n = 0;                                 // nonce counter

        // Key pairs and public keys
        this.s = null;                              // local static key pair
        this.e = null;                              // local ephemeral key pair
        this.rs = null;                             // remote static public key
        this.re = null;                             // remote ephemeral public key

        // State
        this.handshakeComplete = false;
        this.initiator = null;                      // true if initiator, false if responder
    }

    /**
     * Initialize as initiator with responder's static public key
     */
    initializeInitiator(responderStaticPubkey, prologue = new Uint8Array()) {
        this.reset();
        this.initiator = true;
        this.rs = new Uint8Array(responderStaticPubkey);

        this._initializeSymmetric();
        this._mixHash(prologue);
        this._mixHash(this.rs);
    }

    /**
     * Initialize as responder with own static key pair
     */
    initializeResponder(staticKeyPair, prologue = new Uint8Array()) {
        this.reset();
        this.initiator = false;
        this.s = staticKeyPair;

        this._initializeSymmetric();
        this._mixHash(prologue);
        this._mixHash(this.s.publicKey);
    }

    /**
     * Initialize symmetric state with protocol name
     */
    _initializeSymmetric() {
        const protocolName = new TextEncoder().encode(PROTOCOL_NAME);

        if (protocolName.length <= HASHLEN) {
            this.h.set(protocolName);
            // Pad with zeros if needed (already zero-initialized)
        } else {
            this.h.set(sha256(protocolName));
        }

        this.ck.set(this.h);
        this.k = null;
    }

    /**
     * Mix data into handshake hash
     */
    _mixHash(data) {
        // Mix data into hash state: h = SHA256(h || data)
        const combined = new Uint8Array(this.h.length + data.length);
        combined.set(this.h);
        combined.set(data, this.h.length);
        const hash_result = sha256(combined);
        this.h.set(hash_result);
    }

    /**
     * Mix key material into chaining key and derive new symmetric key
     */
    _mixKey(inputKeyMaterial) {
        const output = noiseHKDF(this.ck, inputKeyMaterial, 2);
        this.ck.set(output.slice(0, HASHLEN));
        this.k = output.slice(HASHLEN, HASHLEN + 32);
        this.n = 0;
    }

    /**
     * Encrypt and hash payload
     */
    _encryptAndHash(plaintext) {
        if (!this.k) {
            this._mixHash(plaintext);
            return plaintext;
        }

        const ciphertext = this._encrypt(plaintext);
        this._mixHash(ciphertext);
        return ciphertext;
    }

    /**
     * Decrypt and hash ciphertext
     */
    _decryptAndHash(ciphertext) {
        if (!this.k) {
            // No key yet - return ciphertext as plaintext
            this._mixHash(ciphertext);
            return ciphertext;
        }

        const plaintext = this._decrypt(ciphertext);
        this._mixHash(ciphertext);
        return plaintext;
    }

    /**
     * AEAD encrypt with current key and nonce
     */
    _encrypt(plaintext) {
        if (!this.k) {
            throw new Error('No encryption key available');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        // Matches Python: b'\x00\x00\x00\x00' + n.to_bytes(8, 'big')
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.n / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.n & 0xffffffff, false);              // big-endian low 32 bits

        // Convert Uint8Arrays to Buffers for Node.js crypto
        const keyBuffer = Buffer.from(this.k);
        const nonceBuffer = Buffer.from(nonce);
        const aadBuffer = Buffer.from(this.h);
        const plaintextBuffer = Buffer.from(plaintext);

        try {
            const cipher = createCipheriv('aes-256-gcm', keyBuffer, nonceBuffer);
            cipher.setAAD(aadBuffer);

            let encrypted = cipher.update(plaintextBuffer);
            cipher.final();
            const tag = cipher.getAuthTag();

            // Combine encrypted data + tag
            const ciphertext = Buffer.concat([encrypted, tag]);

            this.n++;

            // Convert back to Uint8Array for consistency
            return new Uint8Array(ciphertext);
        } catch (error) {
            throw new Error(`AES-GCM encryption failed: ${error.message}`);
        }
    }

    /**
     * AEAD decrypt with current key and nonce
     */
    _decrypt(ciphertext) {
        if (!this.k) {
            throw new Error('No decryption key available');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        // Matches Python: b'\x00\x00\x00\x00' + n.to_bytes(8, 'big')
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.n / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.n & 0xffffffff, false);              // big-endian low 32 bits

        // Convert Uint8Arrays to Buffers for Node.js crypto
        const keyBuffer = Buffer.from(this.k);
        const nonceBuffer = Buffer.from(nonce);
        const aadBuffer = Buffer.from(this.h);
        const ciphertextBuffer = Buffer.from(ciphertext);

        // Split ciphertext into encrypted data + tag (last 16 bytes)
        const encrypted = ciphertextBuffer.slice(0, -16);
        const tag = ciphertextBuffer.slice(-16);

        try {
            const decipher = createDecipheriv('aes-256-gcm', keyBuffer, nonceBuffer);
            decipher.setAAD(aadBuffer);
            decipher.setAuthTag(tag);

            let decrypted = decipher.update(encrypted);
            decipher.final();

            this.n++;

            // Convert back to Uint8Array for consistency
            return new Uint8Array(decrypted);
        } catch (error) {
            throw new Error(`AES-GCM decryption failed: ${error.message}`);
        }
    }

    /**
     * Generate ephemeral key pair
     */
    _generateEphemeralKeyPair() {
        let privateKey;
        if (debug.isDebugModeEnabled()) {
            // Use deterministic ephemeral secret in debug mode
            privateKey = debug.getDeterministicEphemeralSecret();
            debug.debugLog("Using deterministic ephemeral secret for Noise handshake");
        } else {
            privateKey = randomBytes(32);
        }
        const publicKey = x25519.getPublicKey(privateKey);
        return { privateKey, publicKey };
    }

    /**
     * Perform Diffie-Hellman
     */
    _dh(keyPair, publicKey) {
        const shared = x25519.getSharedSecret(keyPair.privateKey, publicKey);
        return shared;
    }

    /**
     * Split final chaining key into transport keys
     */
    _split() {
        const output = noiseHKDF(this.ck, new Uint8Array(0), 2);
        const k1 = output.slice(0, 32);  // initiator to responder
        const k2 = output.slice(32, 64); // responder to initiator
        return { k1, k2 };
    }

    /**
     * Get current handshake hash.
     */
    getHandshakeHash() {
        return new Uint8Array(this.h);
    }

    /**
     * Encrypt transport message (post-handshake)
     */
    encrypt(plaintext) {
        if (!this.handshakeComplete) {
            throw new Error('Handshake not complete - cannot encrypt transport messages');
        }
        if (!this.sendKey) {
            throw new Error('Send key not available');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.sendNonce / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.sendNonce & 0xffffffff, false);              // big-endian low 32 bits

        // Convert to Node.js buffers
        const keyBuffer = Buffer.from(this.sendKey);
        const nonceBuffer = Buffer.from(nonce);
        const plaintextBuffer = Buffer.from(plaintext);

        try {
            const cipher = createCipheriv('aes-256-gcm', keyBuffer, nonceBuffer);

            let encrypted = cipher.update(plaintextBuffer);
            cipher.final();

            const tag = cipher.getAuthTag();

            // Combine encrypted data + tag
            const ciphertext = new Uint8Array(encrypted.length + tag.length);
            ciphertext.set(new Uint8Array(encrypted));
            ciphertext.set(new Uint8Array(tag), encrypted.length);

            this.sendNonce++;

            return ciphertext;
        } catch (error) {
            throw new Error(`Transport encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt transport message (post-handshake)
     */
    decrypt(ciphertext) {
        if (!this.handshakeComplete) {
            throw new Error('Handshake not complete - cannot decrypt transport messages');
        }
        if (!this.receiveKey) {
            throw new Error('Receive key not available');
        }

        if (ciphertext.length < 16) {
            throw new Error('Ciphertext too short (must include 16-byte auth tag)');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.receiveNonce / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.receiveNonce & 0xffffffff, false);              // big-endian low 32 bits

        // Convert to Node.js buffers
        const keyBuffer = Buffer.from(this.receiveKey);
        const nonceBuffer = Buffer.from(nonce);
        const ciphertextBuffer = Buffer.from(ciphertext);

        // Split ciphertext into encrypted data + tag (last 16 bytes)
        const encrypted = ciphertextBuffer.slice(0, -16);
        const tag = ciphertextBuffer.slice(-16);

        try {
            const decipher = createDecipheriv('aes-256-gcm', keyBuffer, nonceBuffer);
            decipher.setAuthTag(tag);

            let decrypted = decipher.update(encrypted);
            decipher.final();

            this.receiveNonce++;

            // Convert back to Uint8Array for consistency
            return new Uint8Array(decrypted);
        } catch (error) {
            throw new Error(`Transport decryption failed: ${error.message}`);
        }
    }

    // =================================================================
    // PUBLIC API - Unified Methods (matching Python implementation)
    // =================================================================

    /**
     * Write handshake message (works for both initiator and responder)
     */
    writeMessage(payload = new Uint8Array()) {
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }

        if (this.initiator === true) {
            // Initiator first message: -> e, es
            return this.writeMessageA(payload);
        } else if (this.initiator === false) {
            // Responder second message: <- e, ee
            const result = this.writeMessageB(payload);
            return result.message;
        } else {
            throw new Error('NoiseNK not initialized');
        }
    }

    /**
     * Read handshake message (works for both initiator and responder)
     */
    readMessage(message) {
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }

        if (this.initiator === false) {
            // Responder reading first message: -> e, es
            return this.readMessageA(message);
        } else if (this.initiator === true) {
            // Initiator reading second message: <- e, ee
            const result = this.readMessageB(message);
            return result.payload;
        } else {
            throw new Error('NoiseNK not initialized');
        }
    }

    // =================================================================
    // PUBLIC API - Initiator Methods
    // =================================================================

    /**
     * INITIATOR: Create first handshake message
     * -> e, es
     */
    writeMessageA(payload = new Uint8Array()) {
        if (!this.initiator) {
            throw new Error('Not initialized as initiator');
        }
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }

        // Generate ephemeral key pair
        this.e = this._generateEphemeralKeyPair();

        // -> e: send ephemeral public key
        this._mixHash(this.e.publicKey);

        // -> es: perform DH between our ephemeral and their static
        const dh = this._dh(this.e, this.rs);
        this._mixKey(dh);

        // Encrypt payload (even if empty - required for Noise-NK compatibility)
        const ciphertext = this._encryptAndHash(payload);

        // Return message: ephemeral_pubkey || ciphertext
        const message = new Uint8Array(DHLEN + ciphertext.length);
        message.set(this.e.publicKey);
        message.set(ciphertext, DHLEN);

        return message;
    }

    /**
     * INITIATOR: Process second handshake message
     * <- e, ee
     */
    readMessageB(message) {
        if (!this.initiator) {
            throw new Error('Not initialized as initiator');
        }
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }
        if (message.length < DHLEN) {
            throw new Error('Message too short');
        }

        // <- e: receive ephemeral public key
        this.re = message.slice(0, DHLEN);
        this._mixHash(this.re);

        // <- ee: perform DH between our ephemeral and their ephemeral
        const dh = this._dh(this.e, this.re);
        this._mixKey(dh);

        // Decrypt payload
        const ciphertext = message.slice(DHLEN);
        const payload = this._decryptAndHash(ciphertext);

        // Handshake complete - split keys
        const { k1, k2 } = this._split();
        this.handshakeComplete = true;

        // Store transport keys for initiator
        this.sendKey = k1;      // initiator sends with k1
        this.receiveKey = k2;   // initiator receives with k2
        this.sendNonce = 0;     // start nonce counters at 0
        this.receiveNonce = 0;
        
        // Debug transport keys
        if (debug.isDebugModeEnabled()) {
            debug.debugLog("🔑 JAVASCRIPT INITIATOR: Transport key assignment complete");
            debug.debugLog("  - send_cipher: k1 (initiator->responder)");
            debug.debugLog("  - recv_cipher: k2 (responder->initiator)");
            debug.debugLog("  - JavaScript uses k1 for send, k2 for recv (initiator)");
            debug.debugLog("🔑 JAVASCRIPT INITIATOR: Transport cipher information");
            debug.debugLog(`  - send key: ${Array.from(k1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            debug.debugLog(`  - recv key: ${Array.from(k2).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        }

        return {
            payload,
            sendKey: k1,    // initiator to responder
            receiveKey: k2  // responder to initiator
        };
    }

    // =================================================================
    // PUBLIC API - Responder Methods
    // =================================================================

    /**
     * RESPONDER: Process first handshake message
     * -> e, es
     */
    readMessageA(message) {
        if (this.initiator !== false) {
            throw new Error('Not initialized as responder');
        }
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }
        if (message.length < DHLEN) {
            throw new Error('Message too short');
        }

        // -> e: receive ephemeral public key
        this.re = message.slice(0, DHLEN);
        this._mixHash(this.re);

        // -> es: perform DH between their ephemeral and our static
        const dh = this._dh(this.s, this.re);
        this._mixKey(dh);

        // Decrypt payload
        const ciphertext = message.slice(DHLEN);
        const payload = this._decryptAndHash(ciphertext);

        return payload;
    }

    /**
     * RESPONDER: Create second handshake message
     * <- e, ee
     */
    writeMessageB(payload = new Uint8Array()) {
        if (this.initiator !== false) {
            throw new Error('Not initialized as responder');
        }
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }

        // Generate ephemeral key pair
        this.e = this._generateEphemeralKeyPair();

        // <- e: send ephemeral public key
        this._mixHash(this.e.publicKey);

        // <- ee: perform DH between our ephemeral and their ephemeral
        const dh = this._dh(this.e, this.re);
        this._mixKey(dh);

        // Encrypt payload
        const ciphertext = this._encryptAndHash(payload);

        // Return message: ephemeral_pubkey || ciphertext
        const message = new Uint8Array(DHLEN + ciphertext.length);
        message.set(this.e.publicKey);
        message.set(ciphertext, DHLEN);

        // Handshake complete - split keys
        const { k1, k2 } = this._split();
        this.handshakeComplete = true;

        // Store transport keys for responder
        this.sendKey = k2;      // responder sends with k2
        this.receiveKey = k1;   // responder receives with k1
        this.sendNonce = 0;     // start nonce counters at 0
        this.receiveNonce = 0;

        return {
            message,
            sendKey: k2,    // responder to initiator
            receiveKey: k1  // initiator to responder
        };
    }
}

// Export utility functions for key generation
export function generateStaticKeyPair() {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}
