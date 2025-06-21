/**
 * OpenADP JavaScript SDK
 * 
 * Advanced Data Protection SDK for JavaScript/Node.js
 * Provides cryptographic operations, client implementations, and key management
 * for the OpenADP distributed secret sharing system.
 */

// Export cryptographic primitives
export {
    Point2D,
    Point4D,
    G,
    P,
    Q,
    D,
    hashToPoint,
    hkdf,
    ShamirSecretSharing,
    generateAuthCodes,
    passwordToPin,
    mod,
    modInverse,
    modPow
} from './crypto.js';

// Export client implementations
export {
    OpenADPClient,
    EncryptedOpenADPClient,
    MultiServerClient,
    NoiseNK,
    ERROR_CODES,
    discoverServers,
    scrapeServers
} from './client.js';

// Export key generation and management
export {
    generateEncryptionKey,
    recoverEncryptionKey,
    deriveIdentifiers,
    generateServerAuthCodes,
    convertPasswordToPin,
    generateSalt,
    deriveKeyFromPassword,
    generateRandomIdentifier,
    validateShareData,
    createBackupPackage,
    restoreBackupPackage,
    generateRecoveryPhrase,
    recoverFromRecoveryPhrase
} from './keygen.js';

// Version information
export const VERSION = '1.0.0';

// SDK information
export const SDK_INFO = {
    name: 'OpenADP JavaScript SDK',
    version: VERSION,
    description: 'Advanced Data Protection with distributed secret sharing',
    author: 'OpenADP Contributors',
    license: 'Apache-2.0'
}; 