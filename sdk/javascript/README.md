# OpenADP JavaScript SDK

A JavaScript implementation of the Noise-NK protocol (`Noise_NK_25519_AESGCM_SHA256`) that is compatible with existing Go servers and follows the official Noise Protocol Framework specification.

## Features

- **Specification Compliant**: Follows the official Noise Protocol Framework specification exactly
- **Secure**: Uses AES256-GCM for AEAD encryption and Curve25519 for key exchange  
- **Minimal Dependencies**: Uses only the well-audited Noble crypto libraries
- **Go Compatible**: Tested to work with existing Go Noise-NK implementations
- **Modern JavaScript**: ES modules with full TypeScript support

## Installation

```bash
npm install
```

## Dependencies

- `@noble/curves` - Curve25519 elliptic curve operations
- `@noble/ciphers` - AES-GCM encryption  
- `@noble/hashes` - SHA256 and HKDF implementations

## Protocol Details

This implementation uses the **Noise-NK** pattern with the following components:

- **Pattern**: `NK` (No static key for initiator, Known static key for responder)
- **DH**: `25519` (Curve25519)
- **AEAD**: `AESGCM` (AES256-GCM)
- **Hash**: `SHA256`

### Handshake Flow

```
<- s              (pre-message: responder's static key is known)
...
-> e, es          (initiator sends ephemeral key, performs DH)
<- e, ee          (responder sends ephemeral key, performs DH)
```

## Basic Usage

### Client (Initiator)

```javascript
import { NoiseNK, generateStaticKeyPair } from 'openadp-sdk-js';

// Server's static public key (obtained out-of-band)
const serverPublicKey = new Uint8Array(/* 32 bytes */);

// Create and initialize client
const client = new NoiseNK();
client.initializeInitiator(serverPublicKey);

// Send first handshake message
const message1 = client.writeMessageA(new TextEncoder().encode('Hello server!'));
// ... send message1 to server ...

// Process server's response
const result = client.readMessageB(receivedMessage2);
console.log('Server said:', new TextDecoder().decode(result.payload));

// Now have secure transport keys
const { sendKey, receiveKey } = result;
```

### Server (Responder)

```javascript
import { NoiseNK, generateStaticKeyPair } from 'openadp-sdk-js';

// Generate server's static key pair (do this once, store securely)
const serverKeys = generateStaticKeyPair();

// Create and initialize server  
const server = new NoiseNK();
server.initializeResponder(serverKeys);

// Process client's first message
const payload1 = server.readMessageA(receivedMessage1);
console.log('Client said:', new TextDecoder().decode(payload1));

// Send response
const result = server.writeMessageB(new TextEncoder().encode('Hello client!'));
// ... send result.message to client ...

// Now have secure transport keys
const { sendKey, receiveKey } = result;
```

### Using Helper Functions

```javascript
import { createClient, createServer, generateStaticKeyPair } from 'openadp-sdk-js';

// Server setup
const serverKeys = generateStaticKeyPair();
const server = createServer(serverKeys);

// Client setup  
const client = createClient(serverKeys.publicKey);

// Perform handshake...
```

## API Reference

### Classes

#### `NoiseNK`

The main Noise-NK protocol implementation.

**Methods:**

- `initializeInitiator(responderStaticPubkey, prologue?)` - Initialize as client
- `initializeResponder(staticKeyPair, prologue?)` - Initialize as server  
- `writeMessageA(payload?)` - Create first handshake message (client)
- `readMessageA(message)` - Process first handshake message (server)
- `writeMessageB(payload?)` - Create second handshake message (server)
- `readMessageB(message)` - Process second handshake message (client)

### Functions

#### `generateStaticKeyPair()`

Generate a new Curve25519 key pair for server use.

**Returns:** `{ privateKey: Uint8Array, publicKey: Uint8Array }`

#### `createClient(serverPublicKey, prologue?)`

Create a pre-configured NoiseNK instance for client use.

#### `createServer(staticKeyPair, prologue?)`

Create a pre-configured NoiseNK instance for server use.

## Testing

Run the test suite:

```bash
npm test
```

Run the example:

```bash
npm run example
```

## Security Considerations

- Keep static private keys secure and never transmit them
- Server static public keys should be distributed through a secure channel
- This implementation provides forward secrecy and server authentication
- Transport keys should be used with proper nonce management for ongoing communication

## Compatibility

This implementation is designed to be compatible with:

- Go Noise-NK implementations using the same cipher suite
- Other Noise Protocol Framework implementations
- The official Noise specification (revision 34)

## License

Apache-2.0 