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

const PROTOCOL_NAME = "Noise_NK_25519_AESGCM_SHA256";
const DHLEN = 32;
const HASHLEN = 32;

/**
 * Debug logging helper
 */
function debugLog(message, data) {
    if (process.env.NOISE_DEBUG) {
        console.log(`[NOISE-DEBUG] ${message}`);
        if (data) {
            console.log(`[NOISE-DEBUG] Data: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        }
    }
}

/**
 * HKDF implementation as specified in Noise Protocol Framework
 */
function noiseHKDF(chainingKey, inputKeyMaterial, numOutputs) {
    debugLog('HKDF called', chainingKey);
    debugLog('HKDF input key material', inputKeyMaterial);
    
    // Use Noble's hkdf with the chaining key as salt
    const length = numOutputs * HASHLEN;
    const result = hkdf(sha256, inputKeyMaterial, chainingKey, new Uint8Array(), length);
    
    debugLog('HKDF output', result);
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
        debugLog('Initializing as initiator');
        this.reset();
        this.initiator = true;
        this.rs = new Uint8Array(responderStaticPubkey);
        
        debugLog('Responder static public key', this.rs);
        
        this._initializeSymmetric();
        this._mixHash(prologue);
        this._mixHash(this.rs);
        
        debugLog('Initial handshake hash after initialization', this.h);
    }

    /**
     * Initialize as responder with own static key pair
     */
    initializeResponder(staticKeyPair, prologue = new Uint8Array()) {
        debugLog('Initializing as responder');
        this.reset();
        this.initiator = false;
        this.s = staticKeyPair;
        
        debugLog('Own static public key', this.s.publicKey);
        
        this._initializeSymmetric();
        this._mixHash(prologue);
        this._mixHash(this.s.publicKey);
        
        debugLog('Initial handshake hash after initialization', this.h);
    }

    /**
     * Initialize symmetric state with protocol name
     */
    _initializeSymmetric() {
        const protocolName = new TextEncoder().encode(PROTOCOL_NAME);
        
        debugLog('Initializing symmetric state with protocol name', protocolName);
        
        if (protocolName.length <= HASHLEN) {
            this.h.set(protocolName);
            // Pad with zeros if needed (already zero-initialized)
        } else {
            this.h.set(sha256(protocolName));
        }
        
        this.ck.set(this.h);
        this.k = null;
        
        debugLog('Initial handshake hash', this.h);
        debugLog('Initial chaining key', this.ck);
    }

    /**
     * Mix data into handshake hash
     */
    _mixHash(data) {
        debugLog('Mixing hash with data', data);
        debugLog('Current handshake hash before mix', this.h);
        
        const combined = new Uint8Array(this.h.length + data.length);
        combined.set(this.h);
        combined.set(data, this.h.length);
        
        console.log(`🟨 JS DEBUG: mix_hash - current h: ${Array.from(this.h).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: mix_hash - input data type: ${data.constructor.name}`);
        console.log(`🟨 JS DEBUG: mix_hash - input data length: ${data.length}`);
        console.log(`🟨 JS DEBUG: mix_hash - input data hex: ${Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: mix_hash - combined length: ${combined.length}`);
        console.log(`🟨 JS DEBUG: mix_hash - about to call SHA256 on: ${Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        const hash_result = sha256(combined);
        console.log(`🟨 JS DEBUG: mix_hash - SHA256 result: ${Array.from(hash_result).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        this.h.set(hash_result);
        
        debugLog('Handshake hash after mix', this.h);
    }

    /**
     * Mix key material into chaining key and derive new symmetric key
     */
    _mixKey(inputKeyMaterial) {
        debugLog('Mixing key with input material', inputKeyMaterial);
        debugLog('Current chaining key before mix', this.ck);
        
        console.log(`🟨 JS DEBUG: MIX_KEY OPERATION`);
        console.log(`🟨 JS DEBUG: - chaining key before: ${Array.from(this.ck).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - input key material: ${Array.from(inputKeyMaterial).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        const output = noiseHKDF(this.ck, inputKeyMaterial, 2);
        this.ck.set(output.slice(0, HASHLEN));
        this.k = output.slice(HASHLEN, HASHLEN + 32);
        this.n = 0;
        
        console.log(`🟨 JS DEBUG: - HKDF output: ${Array.from(output).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - new chaining key: ${Array.from(this.ck).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - new symmetric key: ${Array.from(this.k).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        debugLog('Chaining key after mix', this.ck);
        debugLog('Symmetric key after mix', this.k);
    }

    /**
     * Encrypt and hash payload
     */
    _encryptAndHash(plaintext) {
        debugLog('Encrypting and hashing payload', plaintext);
        
        if (!this.k) {
            // No key yet - return plaintext
            debugLog('No key available, returning plaintext');
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
        debugLog('Decrypting and hashing ciphertext', ciphertext);
        
        if (!this.k) {
            // No key yet - return ciphertext as plaintext
            debugLog('No key available, returning ciphertext as plaintext');
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

        debugLog(`Encrypting with nonce ${this.n}`, plaintext);

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        // Matches Python: b'\x00\x00\x00\x00' + n.to_bytes(8, 'big')
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.n / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.n & 0xffffffff, false);              // big-endian low 32 bits

        debugLog('Encryption nonce', nonce);
        debugLog('Encryption key', this.k);
        debugLog('Associated data (handshake hash)', this.h);

        console.log(`🟨 JS DEBUG: AES-GCM ENCRYPT`);
        console.log(`🟨 JS DEBUG: - plaintext length: ${plaintext.length}`);
        console.log(`🟨 JS DEBUG: - plaintext hex: ${Array.from(plaintext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - symmetric key: ${Array.from(this.k).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - nonce counter: ${this.n}`);
        console.log(`🟨 JS DEBUG: - nonce (12 bytes): ${Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - associated data: ${Array.from(this.h).map(b => b.toString(16).padStart(2, '0')).join('')}`);

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
            
            console.log(`🟨 JS DEBUG: - ciphertext: ${Array.from(ciphertext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            
            this.n++;
            debugLog('Encrypted ciphertext', ciphertext);
            
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

        debugLog(`Decrypting with nonce ${this.n}`, ciphertext);

        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        // Matches Python: b'\x00\x00\x00\x00' + n.to_bytes(8, 'big')
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.n / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.n & 0xffffffff, false);              // big-endian low 32 bits

        debugLog('Decryption nonce', nonce);
        debugLog('Decryption key', this.k);
        debugLog('Associated data (handshake hash)', this.h);

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
            debugLog('Decrypted plaintext', decrypted);
            
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
        const privateKey = randomBytes(32);
        const publicKey = x25519.getPublicKey(privateKey);
        debugLog('Generated ephemeral key pair - public key', publicKey);
        return { privateKey, publicKey };
    }

    /**
     * Perform Diffie-Hellman
     */
    _dh(keyPair, publicKey) {
        debugLog('Performing DH with public key', publicKey);
        console.log(`🟨 JS DEBUG: DH OPERATION`);
        console.log(`🟨 JS DEBUG: - private key: ${Array.from(keyPair.privateKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - public key: ${Array.from(publicKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        const shared = x25519.getSharedSecret(keyPair.privateKey, publicKey);
        
        console.log(`🟨 JS DEBUG: - shared secret: ${Array.from(shared).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        debugLog('DH shared secret', shared);
        return shared;
    }

    /**
     * Split final chaining key into transport keys
     */
    _split() {
        debugLog('Splitting chaining key for transport');
        console.log(`🟨 JS DEBUG: SPLITTING TRANSPORT KEYS`);
        console.log(`🟨 JS DEBUG: - final chaining key: ${Array.from(this.ck).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        const output = noiseHKDF(this.ck, new Uint8Array(0), 2);
        const k1 = output.slice(0, 32);  // initiator to responder
        const k2 = output.slice(32, 64); // responder to initiator
        
        console.log(`🟨 JS DEBUG: - transport key k1 (initiator->responder): ${Array.from(k1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - transport key k2 (responder->initiator): ${Array.from(k2).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        debugLog('Transport key 1 (initiator->responder)', k1);
        debugLog('Transport key 2 (responder->initiator)', k2);
        return { k1, k2 };
    }

    /**
     * Get current handshake hash (for debugging)
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
        
        debugLog('Encrypting transport message', plaintext);
        console.log(`🟨 JS DEBUG: TRANSPORT ENCRYPT`);
        console.log(`🟨 JS DEBUG: - plaintext length: ${plaintext.length}`);
        console.log(`🟨 JS DEBUG: - plaintext hex: ${Array.from(plaintext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - send key: ${Array.from(this.sendKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - send nonce: ${this.sendNonce}`);
        
        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.sendNonce / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.sendNonce & 0xffffffff, false);              // big-endian low 32 bits
        
        console.log(`🟨 JS DEBUG: - nonce (12 bytes): ${Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
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
            
            console.log(`🟨 JS DEBUG: - ciphertext: ${Array.from(ciphertext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            debugLog('Transport encrypted ciphertext', ciphertext);
            
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
        
        debugLog('Decrypting transport message', ciphertext);
        console.log(`🟨 JS DEBUG: TRANSPORT DECRYPT`);
        console.log(`🟨 JS DEBUG: - ciphertext length: ${ciphertext.length}`);
        console.log(`🟨 JS DEBUG: - ciphertext hex: ${Array.from(ciphertext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - receive key: ${Array.from(this.receiveKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - receive nonce: ${this.receiveNonce}`);
        
        if (ciphertext.length < 16) {
            throw new Error('Ciphertext too short (must include 16-byte auth tag)');
        }
        
        // Create 96-bit nonce: 4 bytes zeros + 8-byte counter (big-endian) - AES-GCM format
        const nonce = new Uint8Array(12);
        const view = new DataView(nonce.buffer);
        view.setUint32(4, Math.floor(this.receiveNonce / 0x100000000), false); // big-endian high 32 bits
        view.setUint32(8, this.receiveNonce & 0xffffffff, false);              // big-endian low 32 bits
        
        console.log(`🟨 JS DEBUG: - nonce (12 bytes): ${Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
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
            
            console.log(`🟨 JS DEBUG: - decrypted plaintext: ${Array.from(decrypted).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            debugLog('Transport decrypted plaintext', decrypted);
            
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
        debugLog('Writing handshake message', payload);
        
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
        debugLog('Reading handshake message', message);
        
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
        debugLog('INITIATOR: Writing message A (-> e, es)');
        
        if (!this.initiator) {
            throw new Error('Not initialized as initiator');
        }
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }

        // Generate ephemeral key pair
        this.e = this._generateEphemeralKeyPair();
        
        // -> e: send ephemeral public key
        debugLog('-> e: mixing ephemeral public key');
        this._mixHash(this.e.publicKey);
        
        // -> es: perform DH between our ephemeral and their static
        debugLog('-> es: performing DH(e, rs)');
        const dh = this._dh(this.e, this.rs);
        this._mixKey(dh);
        
        // Encrypt payload (even if empty - required for Noise-NK compatibility)
        const ciphertext = this._encryptAndHash(payload);
        
        // Return message: ephemeral_pubkey || ciphertext
        const message = new Uint8Array(DHLEN + ciphertext.length);
        message.set(this.e.publicKey);
        message.set(ciphertext, DHLEN);
        
        debugLog('INITIATOR: Message A complete', message);
        return message;
    }

    /**
     * INITIATOR: Process second handshake message
     * <- e, ee
     */
    readMessageB(message) {
        debugLog('INITIATOR: Reading message B (<- e, ee)');
        
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
        debugLog('<- e: received ephemeral public key', this.re);
        this._mixHash(this.re);
        
        // <- ee: perform DH between our ephemeral and their ephemeral
        debugLog('<- ee: performing DH(e, re)');
        const dh = this._dh(this.e, this.re);
        this._mixKey(dh);
        
        // Decrypt payload
        const ciphertext = message.slice(DHLEN);
        const payload = this._decryptAndHash(ciphertext);
        
        // Handshake complete - split keys
        debugLog('INITIATOR: Handshake complete, splitting keys');
        const { k1, k2 } = this._split();
        this.handshakeComplete = true;
        
        // Store transport keys for initiator
        this.sendKey = k1;      // initiator sends with k1
        this.receiveKey = k2;   // initiator receives with k2
        this.sendNonce = 0;     // start nonce counters at 0
        this.receiveNonce = 0;
        
        console.log(`🟨 JS DEBUG: INITIATOR FINAL KEYS`);
        console.log(`🟨 JS DEBUG: - initiator send key: ${Array.from(k1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - initiator receive key: ${Array.from(k2).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        debugLog('INITIATOR: Final handshake hash', this.h);
        
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
        debugLog('RESPONDER: Reading message A (-> e, es)');
        
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
        debugLog('-> e: received ephemeral public key', this.re);
        this._mixHash(this.re);
        
        // -> es: perform DH between their ephemeral and our static
        debugLog('-> es: performing DH(s, re)');
        const dh = this._dh(this.s, this.re);
        this._mixKey(dh);
        
        // Decrypt payload
        const ciphertext = message.slice(DHLEN);
        const payload = this._decryptAndHash(ciphertext);
        
        debugLog('RESPONDER: Message A processed');
        return payload;
    }

    /**
     * RESPONDER: Create second handshake message
     * <- e, ee
     */
    writeMessageB(payload = new Uint8Array()) {
        debugLog('RESPONDER: Writing message B (<- e, ee)');
        
        if (this.initiator !== false) {
            throw new Error('Not initialized as responder');
        }
        if (this.handshakeComplete) {
            throw new Error('Handshake already complete');
        }

        // Generate ephemeral key pair
        this.e = this._generateEphemeralKeyPair();
        
        // <- e: send ephemeral public key
        debugLog('<- e: mixing ephemeral public key');
        this._mixHash(this.e.publicKey);
        
        // <- ee: perform DH between our ephemeral and their ephemeral  
        debugLog('<- ee: performing DH(e, re)');
        const dh = this._dh(this.e, this.re);
        this._mixKey(dh);
        
        // Encrypt payload
        const ciphertext = this._encryptAndHash(payload);
        
        // Return message: ephemeral_pubkey || ciphertext
        const message = new Uint8Array(DHLEN + ciphertext.length);
        message.set(this.e.publicKey);
        message.set(ciphertext, DHLEN);
        
        // Handshake complete - split keys
        debugLog('RESPONDER: Handshake complete, splitting keys');
        const { k1, k2 } = this._split();
        this.handshakeComplete = true;
        
        // Store transport keys for responder
        this.sendKey = k2;      // responder sends with k2
        this.receiveKey = k1;   // responder receives with k1
        this.sendNonce = 0;     // start nonce counters at 0
        this.receiveNonce = 0;
        
        console.log(`🟨 JS DEBUG: RESPONDER FINAL KEYS`);
        console.log(`🟨 JS DEBUG: - responder send key: ${Array.from(k2).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        console.log(`🟨 JS DEBUG: - responder receive key: ${Array.from(k1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        debugLog('RESPONDER: Final handshake hash', this.h);
        
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