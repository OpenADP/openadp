/**
 * Browser-compatible Noise-NK Protocol Implementation using WebCrypto API
 * This replaces Node.js crypto functions with browser-native WebCrypto
 */

import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';

const PROTOCOL_NAME = "Noise_NK_25519_AESGCM_SHA256";
const DHLEN = 32;
const HASHLEN = 32;

/**
 * Browser-compatible random bytes generation
 */
function randomBytes(size) {
    const bytes = new Uint8Array(size);
    crypto.getRandomValues(bytes);
    return bytes;
}

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
 * Noise-NK Protocol Implementation using WebCrypto API
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

        // Transport keys and counters (separate for send/receive)
        this.sendKey = null;                        // key for sending messages
        this.receiveKey = null;                     // key for receiving messages
        this.sendCounter = 0;                       // counter for sending
        this.receiveCounter = 0;                    // counter for receiving

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
        // Ensure data is a Uint8Array
        if (!data || typeof data.length === 'undefined') {
            console.error('_mixHash: data is not array-like:', data);
            throw new Error('_mixHash: data must be array-like');
        }
        
        // Convert to Uint8Array if needed
        let dataBytes;
        if (data instanceof Uint8Array) {
            dataBytes = data;
        } else if (Array.isArray(data) || data.buffer) {
            dataBytes = new Uint8Array(data);
        } else {
            console.error('_mixHash: invalid data type:', typeof data, data);
            throw new Error('_mixHash: data must be convertible to Uint8Array');
        }
        
        // Mix data into hash state: h = SHA256(h || data)
        const combined = new Uint8Array(this.h.length + dataBytes.length);
        combined.set(this.h);
        combined.set(dataBytes, this.h.length);
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
     * AEAD encrypt with current key and nonce using Noble Ciphers
     */
    _encrypt(plaintext) {
        if (!this.k) {
            throw new Error('No encryption key available');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.n / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.n & 0xffffffff, false);              // big-endian low 32 bits

        try {
            // Use Noble Ciphers AES-GCM with AAD for handshake
            // Noble Ciphers API: gcm(key, nonce, aad?) where aad is optional
            const cipher = this.h.length > 0 ? gcm(this.k, nonce, this.h) : gcm(this.k, nonce);
            const ciphertext = cipher.encrypt(plaintext);

            this.n++;

            return ciphertext;
        } catch (error) {
            throw new Error(`AES-GCM encryption failed: ${error.message}`);
        }
    }

    /**
     * AEAD decrypt with current key and nonce using Noble Ciphers
     */
    _decrypt(ciphertext) {
        if (!this.k) {
            throw new Error('No decryption key available');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.n / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.n & 0xffffffff, false);              // big-endian low 32 bits

        try {
            // Use Noble Ciphers AES-GCM with AAD for handshake
            // Noble Ciphers API: gcm(key, nonce, aad?) where aad is optional
            const cipher = this.h.length > 0 ? gcm(this.k, nonce, this.h) : gcm(this.k, nonce);
            const plaintext = cipher.decrypt(ciphertext);

            this.n++;

            return plaintext;
        } catch (error) {
            throw new Error(`AES-GCM decryption failed: ${error.message}`);
        }
    }

    /**
     * Generate ephemeral key pair
     */
    _generateEphemeralKeyPair() {
        const privateKey = randomBytes(32);
        const publicKey = x25519.getPublicKey(privateKey);
        return { privateKey, publicKey };
    }

    /**
     * Perform Diffie-Hellman operation
     */
    _dh(keyPair, publicKey) {
        return x25519.getSharedSecret(keyPair.privateKey, publicKey);
    }

    /**
     * Split to get final transport keys
     */
    _split() {
        const output = noiseHKDF(this.ck, new Uint8Array(), 2);
        const k1 = output.slice(0, HASHLEN);
        const k2 = output.slice(HASHLEN, HASHLEN + 32);
        return { k1, k2 };
    }

    /**
     * Get handshake hash
     */
    getHandshakeHash() {
        return new Uint8Array(this.h);
    }

    /**
     * Encrypt transport message
     */
    encrypt(plaintext) {
        if (!this.handshakeComplete) {
            throw new Error('Handshake not complete');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian)
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.sendCounter / 0x100000000), false);
        view.setUint32(8, this.sendCounter & 0xffffffff, false);

        console.log(`🔍 Transport encrypt: sendCounter=${this.sendCounter}, nonce=${Array.from(nonce).map(x => x.toString(16).padStart(2, '0')).join('')}, sendKey=${Array.from(this.sendKey.slice(0, 8)).map(x => x.toString(16).padStart(2, '0')).join('')}...`);

        try {
            // Use Noble Ciphers AES-GCM (no AAD for transport messages)
            const cipher = gcm(this.sendKey, nonce); // key, nonce, no AAD
            const ciphertext = cipher.encrypt(plaintext);

            console.log(`🔍 Transport encrypt result: ${Array.from(ciphertext.slice(0, 16)).map(x => x.toString(16).padStart(2, '0')).join('')}...`);

            this.sendCounter++;

            return ciphertext;
        } catch (error) {
            throw new Error(`Transport encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt transport message
     */
    decrypt(ciphertext) {
        if (!this.handshakeComplete) {
            throw new Error('Handshake not complete');
        }

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian)
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.receiveCounter / 0x100000000), false);
        view.setUint32(8, this.receiveCounter & 0xffffffff, false);

        console.log(`🔍 Transport decrypt: receiveCounter=${this.receiveCounter}, nonce=${Array.from(nonce).map(x => x.toString(16).padStart(2, '0')).join('')}, receiveKey=${Array.from(this.receiveKey.slice(0, 8)).map(x => x.toString(16).padStart(2, '0')).join('')}...`);
        console.log(`🔍 Transport decrypt ciphertext: ${Array.from(ciphertext.slice(0, 16)).map(x => x.toString(16).padStart(2, '0')).join('')}...`);

        try {
            // Use Noble Ciphers AES-GCM (no AAD for transport messages)
            const cipher = gcm(this.receiveKey, nonce); // key, nonce, no AAD
            const plaintext = cipher.decrypt(ciphertext);

            console.log(`🔍 Transport decrypt result: ${Array.from(plaintext.slice(0, 16)).map(x => x.toString(16).padStart(2, '0')).join('')}...`);

            this.receiveCounter++;

            return plaintext;
        } catch (error) {
            console.log(`❌ Transport decrypt error: ${error.message}`);
            throw new Error(`Transport decryption failed: ${error.message}`);
        }
    }

    /**
     * Write handshake message (generic)
     */
    writeMessage(payload = new Uint8Array()) {
        if (this.initiator) {
            return this.writeMessageA(payload);
        } else {
            return this.writeMessageB(payload);
        }
    }

    /**
     * Read handshake message (generic)
     */
    readMessage(message) {
        if (this.initiator) {
            return this.readMessageB(message);
        } else {
            return this.readMessageA(message);
        }
    }

    /**
     * Write message A (initiator -> responder)
     */
    writeMessageA(payload = new Uint8Array()) {
        if (!this.initiator) {
            throw new Error('Only initiator can write message A');
        }

        // Generate ephemeral key pair
        this.e = this._generateEphemeralKeyPair();

        // Build message: e, es, payload
        let message = new Uint8Array(this.e.publicKey);

        // Mix ephemeral public key into hash
        this._mixHash(this.e.publicKey);

        // Perform es = DH(e, rs)
        const es = this._dh(this.e, this.rs);
        this._mixKey(es);

        // Encrypt and authenticate payload
        const encryptedPayload = this._encryptAndHash(payload);

        // Combine message parts
        const finalMessage = new Uint8Array(message.length + encryptedPayload.length);
        finalMessage.set(message);
        finalMessage.set(encryptedPayload, message.length);

        return finalMessage;
    }

    /**
     * Read message B (initiator <- responder)
     */
    readMessageB(message) {
        if (!this.initiator) {
            throw new Error('Only initiator can read message B');
        }

        let offset = 0;

        // Extract remote ephemeral public key
        this.re = message.slice(offset, offset + DHLEN);
        offset += DHLEN;

        // Mix remote ephemeral into hash
        this._mixHash(this.re);

        // Perform ee = DH(e, re)
        const ee = this._dh(this.e, this.re);
        this._mixKey(ee);

        // Extract and decrypt payload
        const encryptedPayload = message.slice(offset);
        const payload = this._decryptAndHash(encryptedPayload);

        // Handshake complete
        this.handshakeComplete = true;
        const keys = this._split();
        // Initiator: sends with k1, receives with k2
        this.sendKey = keys.k1;
        this.receiveKey = keys.k2;
        this.sendCounter = 0;
        this.receiveCounter = 0;

        return payload;
    }

    /**
     * Read message A (responder <- initiator)
     */
    readMessageA(message) {
        if (this.initiator) {
            throw new Error('Only responder can read message A');
        }

        let offset = 0;

        // Extract remote ephemeral public key
        this.re = message.slice(offset, offset + DHLEN);
        offset += DHLEN;

        // Mix remote ephemeral into hash
        this._mixHash(this.re);

        // Perform es = DH(s, re)
        const es = this._dh(this.s, this.re);
        this._mixKey(es);

        // Extract and decrypt payload
        const encryptedPayload = message.slice(offset);
        const payload = this._decryptAndHash(encryptedPayload);

        return payload;
    }

    /**
     * Write message B (responder -> initiator)
     */
    writeMessageB(payload = new Uint8Array()) {
        if (this.initiator) {
            throw new Error('Only responder can write message B');
        }

        // Generate ephemeral key pair
        this.e = this._generateEphemeralKeyPair();

        // Build message: e, ee, payload
        let message = new Uint8Array(this.e.publicKey);

        // Mix ephemeral public key into hash
        this._mixHash(this.e.publicKey);

        // Perform ee = DH(e, re)
        const ee = this._dh(this.e, this.re);
        this._mixKey(ee);

        // Encrypt and authenticate payload
        const encryptedPayload = this._encryptAndHash(payload);

        // Combine message parts
        const finalMessage = new Uint8Array(message.length + encryptedPayload.length);
        finalMessage.set(message);
        finalMessage.set(encryptedPayload, message.length);

        // Handshake complete
        this.handshakeComplete = true;
        const keys = this._split();
        // Responder: sends with k2, receives with k1
        this.sendKey = keys.k2;
        this.receiveKey = keys.k1;
        this.sendCounter = 0;
        this.receiveCounter = 0;

        return finalMessage;
    }
}

/**
 * Generate a static key pair for Noise-NK
 */
export function generateStaticKeyPair() {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
} 