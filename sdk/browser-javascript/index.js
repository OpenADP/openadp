/**
 * OpenADP JavaScript SDK
 * 
 * Provides Noise-NK protocol implementation for secure communication
 * compatible with OpenADP servers.
 */

import { NoiseNK, generateStaticKeyPair } from './noise-nk.js';

// Re-export main classes
export { NoiseNK, generateStaticKeyPair };

// Version and protocol information
export const VERSION = '0.1.3';
export const SUPPORTED_PROTOCOLS = ['Noise_NK_25519_AESGCM_SHA256'];

/**
 * Create a new Noise-NK instance for client use
 * @param {Uint8Array} serverPublicKey - The server's static public key
 * @param {Uint8Array} prologue - Optional prologue data
 * @returns {NoiseNK} Configured Noise-NK instance ready for handshake
 */
export function createClient(serverPublicKey, prologue = new Uint8Array()) {
    const client = new NoiseNK();
    client.initializeInitiator(serverPublicKey, prologue);
    return client;
}

/**
 * Create a new Noise-NK instance for server use
 * @param {Object} staticKeyPair - The server's static key pair {privateKey, publicKey}
 * @param {Uint8Array} prologue - Optional prologue data
 * @returns {NoiseNK} Configured Noise-NK instance ready for handshake
 */
export function createServer(staticKeyPair, prologue = new Uint8Array()) {
    const server = new NoiseNK();
    server.initializeResponder(staticKeyPair, prologue);
    return server;
}

/**
 * @openadp/ocrypt - Nation-state resistant password hashing
 * 
 * This package provides a simple 2-function API for distributed password hashing
 * using OpenADP's Oblivious Pseudo Random Function (OPRF) cryptography.
 * 
 * @author OpenADP Team <contact@openadp.org>
 * @license MIT
 * @version 0.1.3
 */

export { register, recover, OcryptError } from './ocrypt.js'; 
