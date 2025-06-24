# OpenADP Browser JavaScript SDK

Browser-compatible JavaScript SDK for OpenADP distributed cryptography.

## Installation

Include the files directly in your web application or use as ES modules:

```html
<script type="module">
  import { register, recover } from './path/to/sdk/browser-javascript/ocrypt.js';
</script>
```

## Usage

```javascript
import { register, recover } from './path/to/openadp/sdk/browser-javascript/ocrypt.js';

// Register (protect a secret)
const userID = 'alice@example.com';
const appID = 'my-secure-app';
const secret = new TextEncoder().encode('my secret data');
const pin = 'user-password';
const maxGuesses = 10;

const metadata = await register(userID, appID, secret, pin, maxGuesses);

// Store metadata alongside user record (it's safe to store anywhere)
localStorage.setItem('backup_metadata', JSON.stringify(Array.from(metadata)));

// Later, recover the secret
const storedMetadata = new Uint8Array(JSON.parse(localStorage.getItem('backup_metadata')));
const { secret: recoveredSecret, remaining, updatedMetadata } = await recover(storedMetadata, pin);

const recoveredData = new TextDecoder().decode(recoveredSecret);
console.log('Recovered:', recoveredData);
```

## Features

- **Browser-compatible**: Uses WebCrypto API instead of Node.js crypto
- **Distributed security**: Secrets protected across multiple independent servers
- **Nation-state resistant**: Even simple PINs become secure
- **Automatic backup refresh**: Maintains security over time
- **No dependencies**: Except for @noble/hashes for cryptographic primitives

## Files

- `ocrypt.js` - Main API (register/recover functions)
- `client.js` - OpenADP network client
- `keygen.js` - Key generation and recovery
- `crypto.js` - Cryptographic primitives
- `noise-nk.js` - Noise protocol implementation

## Differences from Node.js SDK

This browser SDK differs from the Node.js version in several ways:

- Uses `crypto.getRandomValues()` instead of Node.js `crypto.randomBytes()`
- Uses WebCrypto API for AES-GCM encryption
- Imports browser-compatible modules
- No Buffer support (uses Uint8Array)

## License

MIT 