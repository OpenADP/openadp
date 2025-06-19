/**
 * OpenADP Crypto Utilities
 * 
 * JavaScript implementation that matches the crypto format used in:
 * - cmd/openadp-encrypt/main.go  
 * - cmd/openadp-decrypt/main.go
 * 
 * Uses ChaCha20-Poly1305 AEAD with the same file format:
 * [metadata_length][metadata][nonce][encrypted_data]
 */

// Constants matching Go implementation
const NONCE_SIZE = 12; // ChaCha20-Poly1305 nonce size
const KEY_SIZE = 32;   // ChaCha20-Poly1305 key size

/**
 * Encrypts data using ChaCha20-Poly1305 in OpenADP format
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} key - 32-byte encryption key
 * @param {Object} metadata - Metadata object (will be JSON serialized)
 * @returns {Uint8Array} Encrypted blob in OpenADP format
 */
export async function encryptOpenADPFormat(plaintext, key, metadata) {
  if (key.length !== KEY_SIZE) {
    throw new Error(`Key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }

  // Generate random nonce (12 bytes for ChaCha20-Poly1305)
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  
  // Serialize metadata to JSON
  const metadataJSON = JSON.stringify(metadata);
  const metadataBytes = new TextEncoder().encode(metadataJSON);
  
  // Import key for WebCrypto API
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'ChaCha20-Poly1305' },
    false,
    ['encrypt']
  );
  
  // Encrypt using ChaCha20-Poly1305 with metadata as Additional Authenticated Data (AAD)
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'ChaCha20-Poly1305',
      iv: nonce,
      additionalData: metadataBytes
    },
    cryptoKey,
    plaintext
  );
  
  const ciphertextBytes = new Uint8Array(ciphertext);
  
  // Create OpenADP format: [metadata_length][metadata][nonce][encrypted_data]
  const metadataLength = metadataBytes.length;
  const totalLength = 4 + metadataLength + NONCE_SIZE + ciphertextBytes.length;
  const result = new Uint8Array(totalLength);
  
  let offset = 0;
  
  // Write metadata length (4 bytes, little endian)
  writeUint32LE(result, offset, metadataLength);
  offset += 4;
  
  // Write metadata
  result.set(metadataBytes, offset);
  offset += metadataLength;
  
  // Write nonce
  result.set(nonce, offset);
  offset += NONCE_SIZE;
  
  // Write encrypted data
  result.set(ciphertextBytes, offset);
  
  return result;
}

/**
 * Decrypts data using ChaCha20-Poly1305 from OpenADP format
 * @param {Uint8Array} encryptedBlob - Encrypted blob in OpenADP format
 * @param {Uint8Array} key - 32-byte encryption key
 * @returns {Object} { plaintext: Uint8Array, metadata: Object }
 */
export async function decryptOpenADPFormat(encryptedBlob, key) {
  if (key.length !== KEY_SIZE) {
    throw new Error(`Key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }

  // Validate minimum file size
  const minSize = 4 + 1 + NONCE_SIZE + 16; // metadata_length + minimal_metadata + nonce + auth_tag
  if (encryptedBlob.length < minSize) {
    throw new Error(`Encrypted blob too small: ${encryptedBlob.length} bytes (minimum ${minSize})`);
  }

  // Parse OpenADP format: [metadata_length][metadata][nonce][encrypted_data]
  let offset = 0;
  
  // Read metadata length (4 bytes, little endian)
  const metadataLength = readUint32LE(encryptedBlob, offset);
  offset += 4;
  
  // Validate metadata length
  if (metadataLength > encryptedBlob.length - 4 - NONCE_SIZE - 16) {
    throw new Error(`Invalid metadata length: ${metadataLength}`);
  }
  
  // Extract metadata
  const metadataBytes = encryptedBlob.slice(offset, offset + metadataLength);
  offset += metadataLength;
  
  // Extract nonce
  const nonce = encryptedBlob.slice(offset, offset + NONCE_SIZE);
  offset += NONCE_SIZE;
  
  // Extract ciphertext
  const ciphertext = encryptedBlob.slice(offset);
  
  // Parse metadata JSON
  let metadata;
  try {
    const metadataJSON = new TextDecoder().decode(metadataBytes);
    metadata = JSON.parse(metadataJSON);
  } catch (error) {
    throw new Error(`Failed to parse metadata: ${error.message}`);
  }
  
  // Import key for WebCrypto API
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'ChaCha20-Poly1305' },
    false,
    ['decrypt']
  );
  
  // Decrypt using ChaCha20-Poly1305 with metadata as AAD
  let plaintext;
  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'ChaCha20-Poly1305',
        iv: nonce,
        additionalData: metadataBytes
      },
      cryptoKey,
      ciphertext
    );
    plaintext = new Uint8Array(decrypted);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message} (wrong key or corrupted data)`);
  }
  
  return { plaintext, metadata };
}

/**
 * Encrypts a notes container using OpenADP format
 * @param {Object} notesContainer - Notes container object
 * @param {Uint8Array} key - 32-byte encryption key
 * @param {string} deviceId - Device identifier
 * @returns {Uint8Array} Encrypted blob
 */
export async function encryptNotesContainer(notesContainer, key, deviceId) {
  // Create metadata matching openadp-encrypt.go Metadata struct
  const metadata = {
    version: "1.0",
    app_id: "private-notes-demo", 
    device_id: deviceId,
    created: Date.now()
  };
  
  // Serialize notes container to JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(notesContainer));
  
  return await encryptOpenADPFormat(plaintext, key, metadata);
}

/**
 * Decrypts a notes container from OpenADP format
 * @param {Uint8Array} encryptedBlob - Encrypted blob
 * @param {Uint8Array} key - 32-byte encryption key
 * @returns {Object} Notes container object
 */
export async function decryptNotesContainer(encryptedBlob, key) {
  const { plaintext, metadata } = await decryptOpenADPFormat(encryptedBlob, key);
  
  // Parse notes container JSON
  try {
    const notesJSON = new TextDecoder().decode(plaintext);
    const notesContainer = JSON.parse(notesJSON);
    
    // Return both notes and metadata for validation
    return { notesContainer, metadata };
  } catch (error) {
    throw new Error(`Failed to parse notes container: ${error.message}`);
  }
}

/**
 * Writes a 32-bit unsigned integer in little-endian format
 * @param {Uint8Array} buffer - Target buffer
 * @param {number} offset - Offset to write at
 * @param {number} value - Value to write
 */
function writeUint32LE(buffer, offset, value) {
  buffer[offset] = value & 0xFF;
  buffer[offset + 1] = (value >> 8) & 0xFF;
  buffer[offset + 2] = (value >> 16) & 0xFF;
  buffer[offset + 3] = (value >> 24) & 0xFF;
}

/**
 * Reads a 32-bit unsigned integer in little-endian format
 * @param {Uint8Array} buffer - Source buffer
 * @param {number} offset - Offset to read from
 * @returns {number} The read value
 */
function readUint32LE(buffer, offset) {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  ) >>> 0; // Unsigned right shift to ensure unsigned 32-bit
}

/**
 * Generates a random device ID
 * @returns {string} Random device ID
 */
export function generateDeviceId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Generates content-addressable hash for notes
 * @param {string} content - Note content
 * @returns {Promise<string>} Content hash (first 16 hex chars)
 */
export async function hashContent(content) {
  // Normalize content: trim and lowercase for consistent hashing
  const normalized = content.trim().toLowerCase();
  const encoder = new TextEncoder();
  const data = encoder.encode(normalized);
  
  // Generate SHA-256 hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  
  // Return first 16 characters of hex hash for readability
  return Array.from(hashArray.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Validates that ChaCha20-Poly1305 is supported
 * @returns {boolean} True if supported
 */
export function isChaCha20Poly1305Supported() {
  return 'subtle' in crypto && 'ChaCha20-Poly1305' in crypto.subtle;
}

/**
 * Fallback encryption using AES-GCM if ChaCha20-Poly1305 is not available
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} key - 32-byte encryption key
 * @param {Object} metadata - Metadata object
 * @returns {Uint8Array} Encrypted blob (with modified metadata indicating AES-GCM)
 */
export async function encryptOpenADPFormatFallback(plaintext, key, metadata) {
  // Use AES-GCM as fallback
  const modifiedMetadata = { ...metadata, encryption: "AES-GCM-256" };
  
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const metadataJSON = JSON.stringify(modifiedMetadata);
  const metadataBytes = new TextEncoder().encode(metadataJSON);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: metadataBytes
    },
    cryptoKey,
    plaintext
  );
  
  const ciphertextBytes = new Uint8Array(ciphertext);
  const metadataLength = metadataBytes.length;
  const totalLength = 4 + metadataLength + 12 + ciphertextBytes.length;
  const result = new Uint8Array(totalLength);
  
  let offset = 0;
  writeUint32LE(result, offset, metadataLength); offset += 4;
  result.set(metadataBytes, offset); offset += metadataLength;
  result.set(nonce, offset); offset += 12;
  result.set(ciphertextBytes, offset);
  
  return result;
}

// Export utility functions
export { NONCE_SIZE, KEY_SIZE, writeUint32LE, readUint32LE }; 