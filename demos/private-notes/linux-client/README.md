# Private Notes - Linux PWA Client

A Progressive Web App implementation of Private Notes demonstrating OpenADP distributed cryptographic trust.

## Overview

This is the Linux desktop implementation of Private Notes, built as a Progressive Web App (PWA) that works in modern browsers. It showcases OpenADP's distributed secret sharing through a simple, secure notes application.

## Features

- 🔒 **Distributed Encryption**: Notes encrypted using OpenADP's threshold cryptography
- 🌐 **Cross-Device Sync**: Seamless synchronization via Cloudflare R2
- 📱 **Installable PWA**: Install as a desktop app from your browser
- 🔄 **Offline-First**: Full functionality without internet connection
- 🎨 **Clean UI**: Simple, distraction-free interface
- 🔐 **PIN Security**: Secure PIN-based access with recovery options

## Quick Start

### Prerequisites

- Modern browser (Chrome 90+, Firefox 88+, Edge 90+)
- Node.js 16+ (for development)
- Git

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/openadp/openadp.git
   cd openadp/demos/private-notes/linux-client
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start development server**:
   ```bash
   npm run dev
   ```

4. **Open in browser**:
   ```
   http://localhost:3000
   ```

5. **Install as PWA** (optional):
   - Click the install button in your browser's address bar
   - Or use browser menu: "Install Private Notes..."

### Production Build

```bash
npm run build
npm run serve
```

## Usage

### First Time Setup

1. **Welcome Screen**: Learn about OpenADP and distributed trust
2. **Create PIN**: Choose a strong 6-8 digit PIN (remember this!)
3. **Server Configuration**: Automatic discovery of OpenADP servers
4. **Create First Note**: Write your first encrypted note

### Daily Usage

1. **Enter PIN**: Unlock your notes with your PIN
2. **Browse Notes**: View your encrypted notes list
3. **Create/Edit**: Add or modify notes with the built-in editor
4. **Sync**: Notes automatically sync across devices when online

### Recovery

If you forget your PIN:
1. Use the "Forgot PIN?" option on the login screen
2. Follow the OpenADP distributed recovery process
3. Recover your PIN using the threshold cryptography system

## Architecture

### Technology Stack

- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3
- **Storage**: IndexedDB for local storage
- **Sync**: Cloudflare R2 for cloud storage
- **Crypto**: Web Crypto API + OpenADP integration
- **PWA**: Service Worker for offline functionality

### File Structure

```
src/
├── js/
│   ├── app.js              # Main application entry point
│   ├── notes.js            # Notes management logic
│   ├── sync.js             # Cloud synchronization
│   ├── ui.js               # User interface components
│   └── openadp-client.js   # OpenADP integration
├── css/
│   ├── main.css            # Main styles
│   └── components.css      # Component-specific styles
├── html/
│   ├── index.html          # Main application page
│   └── offline.html        # Offline fallback page
└── assets/
    ├── icons/              # PWA icons
    ├── images/             # Application images
    └── manifest.json       # PWA manifest
```

### Data Flow

```
User Input → PIN Entry → OpenADP Key Derivation → 
AES Encryption → IndexedDB Storage → Cloudflare R2 Sync
```

## Development

### Available Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Build for production
- `npm run serve` - Serve production build locally
- `npm run test` - Run test suite
- `npm run lint` - Lint code
- `npm run format` - Format code with Prettier

### Development Workflow

1. **Feature Development**:
   ```bash
   git checkout -b feature/your-feature
   npm run dev
   # Make changes
   npm run test
   npm run lint
   ```

2. **Testing**:
   ```bash
   npm run test           # Unit tests
   npm run test:e2e       # End-to-end tests
   npm run test:security  # Security tests
   ```

3. **Building**:
   ```bash
   npm run build
   npm run serve
   # Test production build
   ```

### Key Components

#### OpenADP Integration (`src/js/openadp-client.js`)
```javascript
class OpenADPClient {
  async deriveKey(pin, deviceId, appId) {
    // Integrate with OpenADP servers for key derivation
  }
  
  async recoverKey(recoveryData) {
    // Implement PIN recovery via threshold cryptography
  }
}
```

#### Notes Management (`src/js/notes.js`)
```javascript
class NotesManager {
  async createNote(title, content) {
    // Encrypt and store note locally and in cloud
  }
  
  async syncNotes() {
    // Synchronize with Cloudflare R2
  }
}
```

#### UI Components (`src/js/ui.js`)
```javascript
class UIManager {
  renderNotesList(notes) {
    // Render notes list with encryption indicators
  }
  
  showSyncStatus(status) {
    // Display sync status and security indicators
  }
}
```

### Security Considerations

- **PIN Storage**: Never store PIN in plaintext
- **Encryption**: Use AES-256-GCM for note content
- **Transport**: All network requests use HTTPS
- **Validation**: Sanitize all user inputs
- **Error Handling**: Never expose sensitive data in errors

### Testing

#### Unit Tests
```bash
npm run test:unit
```

Tests cover:
- OpenADP integration
- Encryption/decryption
- Local storage operations
- Sync functionality

#### Integration Tests
```bash
npm run test:integration
```

Tests cover:
- Complete user workflows
- Cross-device synchronization
- Error recovery scenarios

#### Security Tests
```bash
npm run test:security
```

Tests cover:
- Cryptographic correctness
- Data leakage prevention
- Attack resistance

## Deployment

### GitHub Pages

1. **Build for production**:
   ```bash
   npm run build
   ```

2. **Deploy to GitHub Pages**:
   ```bash
   npm run deploy
   ```

3. **Access at**: `https://openadp.github.io/private-notes/`

### Custom Domain

1. **Configure Cloudflare**:
   - Point `private-notes.openadp.org` to GitHub Pages
   - Enable HTTPS and security features

2. **Update configuration**:
   ```javascript
   // src/js/config.js
   const CONFIG = {
     domain: 'private-notes.openadp.org',
     r2Bucket: 'openadp-private-notes-demo'
   };
   ```

## Configuration

### Environment Variables

Create `.env` file:
```env
# OpenADP Configuration
OPENADP_SERVERS=server1.openadp.org,server2.openadp.org,server3.openadp.org

# Cloudflare R2 Configuration
R2_ACCOUNT_ID=your-account-id
R2_ACCESS_KEY_ID=your-access-key
R2_SECRET_ACCESS_KEY=your-secret-key
R2_BUCKET_NAME=openadp-private-notes-demo

# Application Configuration
APP_VERSION=1.0.0
DEBUG_MODE=false
```

### Server Configuration

The app automatically discovers OpenADP servers, but you can manually configure:

```javascript
// src/js/config.js
const OPENADP_CONFIG = {
  servers: [
    'https://server1.openadp.org',
    'https://server2.openadp.org', 
    'https://server3.openadp.org'
  ],
  threshold: 2,
  timeout: 5000
};
```

## Troubleshooting

### Common Issues

**PWA won't install**:
- Ensure HTTPS is enabled
- Check manifest.json is valid
- Verify service worker registration

**Sync not working**:
- Check internet connection
- Verify Cloudflare R2 credentials
- Check browser console for errors

**PIN recovery fails**:
- Ensure at least 2 OpenADP servers are available
- Check server connectivity
- Verify recovery data integrity

**Performance issues**:
- Clear browser cache and IndexedDB
- Check for large notes causing slowdown
- Monitor memory usage in DevTools

### Debug Mode

Enable debug mode in browser console:
```javascript
localStorage.setItem('debug', 'true');
location.reload();
```

This enables:
- Detailed logging
- Crypto operation timing
- Sync status information
- Error stack traces

## Contributing

### Code Style

- Use ES6+ features
- Follow Prettier formatting
- Write JSDoc comments for public functions
- Use async/await for asynchronous operations

### Pull Request Process

1. Fork the repository
2. Create feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit pull request with clear description

### Security

If you discover security vulnerabilities:
1. **Do not** create public issues
2. Email security@openadp.org
3. Include detailed reproduction steps
4. Allow time for responsible disclosure

## License

This project is licensed under the MIT License - see the [LICENSE](../../../LICENSE) file for details.

## Support

- **Documentation**: [OpenADP Docs](https://docs.openadp.org)
- **Community**: [GitHub Discussions](https://github.com/openadp/openadp/discussions)
- **Issues**: [GitHub Issues](https://github.com/openadp/openadp/issues)
- **Email**: support@openadp.org

---

**Demo Goal**: Showcase OpenADP's distributed cryptographic trust through a practical, secure notes application that developers can learn from and build upon. 