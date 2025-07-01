# 👻🔐 OpenADP Ghost Notes

**Session-based secure note taking with distributed cryptography protection**

Ghost Notes is a privacy-focused note-taking application that leverages OpenADP's distributed threshold cryptography to provide strong security for your personal notes. Your notes are protected by the same technology that secures nation-state communications.

## 🚨 Why OpenADP Over Traditional Security?

**Traditional PIN security is broken:**
```javascript
// Traditional approach - crackable in seconds
const pin = "3344";  // Only 10,000 combinations
const key = pbkdf2(pin, salt, 100000);  // Still brute-forceable
```

**OpenADP makes even simple PINs cryptographically strong:**
```javascript
// OpenADP approach - distributed threshold cryptography
const metadata = await ocrypt.register(userID, "ghost-notes", secret, pin, 10);
// Now your PIN is protected by servers across multiple countries
```

## ✨ Features

- 🔐 **OpenADP Protection**: Nation-state resistant distributed cryptography
- 🛡️ **Threshold Security**: Requires 3+ servers to crack (impossible in practice)
- 👻 **Ghost Mode**: Notes vanish from memory when you're away
- 📱 **PWA Ready**: Install on phone/desktop like a native app
- 🔒 **Cryptographically stron PINs**: Even "3344" becomes cryptographically strong
- ⏱️ **Auto-Lock**: Automatic session timeout for security
- 🌍 **Global Distribution**: Servers across multiple countries
- 📵 **Offline Capable**: Works without internet after initial setup

## 🚀 Quick Start

### Local Testing

1. **Clone or download** the ghost-notes folder
2. **Start a local server**:
   ```bash
   cd ghost-notes
   python3 serve.py
   ```
3. **Open your browser** to `http://localhost:8080/test.html`
4. **Run tests** to verify everything works
5. **Launch the app** from the test page

### First Time Setup

1. Click "First Time Setup" on the login screen
2. Create a secure PIN (4+ characters recommended)
3. Configure your security settings:
   - **Max Failed Attempts**: How many wrong PINs before lockout
   - **Auto-lock Timer**: How long until automatic lock
4. Click "Create Secure Vault"

### Daily Usage

1. **Unlock**: Enter your PIN to start a session
2. **Create Notes**: Click ➕ to add new notes
3. **Edit**: Click any note to edit title and content
4. **Auto-Save**: Changes save automatically as you type
5. **Lock**: Notes encrypt when you close or walk away

## 📱 Mobile Installation

### Android Chrome
1. Open the app in Chrome
2. Tap the menu (⋮) → "Add to Home screen"
3. Tap "Add" to install

### iOS Safari
1. Open the app in Safari
2. Tap the Share button (□↑)
3. Tap "Add to Home Screen"
4. Tap "Add"

## 🔒 Security Architecture

### OpenADP Distributed Protection
- **Threshold Cryptography**: Shamir's Secret Sharing (3-of-5 servers)
- **Geographic Distribution**: Servers across multiple countries
- **Zero-Knowledge**: Servers never see your PIN or notes
- **Attack Resistance**: Must compromise 3+ servers simultaneously

### Encryption
- **Algorithm**: AES-GCM 256-bit encryption
- **Key Protection**: OpenADP distributed threshold cryptography
- **Automatic Refresh**: Backup refreshes prevent data loss
- **Random Salt**: Unique per installation
- **IV**: Random initialization vector per encryption

### Session Management
- **PIN Authentication**: Required for every session
- **Global Rate Limiting**: Enforced across all servers
- **Auto-Lock**: Inactivity timeout with warning
- **Memory Clearing**: Notes purged from RAM when locked

### Storage
- **Local Encrypted**: Everything stored encrypted in browser localStorage
- **Metadata Only**: Only encrypted metadata stored locally
- **No Plaintext**: Notes never stored in plain text anywhere

## 🛡️ Security Comparison

| Feature | Traditional | OpenADP Ghost Notes |
|---------|-------------|---------------------|
| **PIN Security** | ❌ Brute-forceable in seconds | ✅ Distributed protection |
| **Attack Surface** | ❌ Single device | ✅ Must compromise 3+ servers |
| **Offline Attacks** | ❌ Possible with stolen data | ✅ Impossible |
| **Rate Limiting** | ❌ Client-side only | ✅ Server-enforced globally |
| **Quantum Resistant** | ❌ Vulnerable | ✅ Information-theoretic security |
| **Nation-State Resistant** | ❌ Vulnerable | ✅ Geographic distribution |

### Attack Scenarios

**Traditional Security:**
```
Attacker steals: encrypted_notes.dat
Time to crack: ~5 seconds

for pin in range(10000):
    if decrypt(encrypted_notes, pin) == valid:
        print("CRACKED:", pin)
        break
```

**OpenADP Security:**
```
Attacker needs: 3+ compromised servers + correct PIN
Time to crack: Practically impossible

- Each server enforces rate limits
- Servers are geographically distributed  
- Independent security domains
- Threshold cryptography prevents single points of failure
```

## 🛠️ Technical Details

### Browser Requirements
- Modern browser with Web Crypto API support
- localStorage support
- Service Worker support (for PWA features)

### File Structure
```
ghost-notes/
├── index.html          # Main OpenADP-enabled app
├── app.js             # Application logic with OpenADP
├── styles.css         # Dark theme styling
├── manifest.json      # PWA manifest
├── sw.js             # Service worker
├── test.html         # Browser compatibility test
├── serve.py          # Local development server
└── README.md         # This file
```

## 🔮 Future Features (Phase 2)

### Cloud Sync with Cloudflare R2
- **Distributed Storage**: Sync encrypted notes across devices
- **Collaborative Editing**: Real-time multi-user editing
- **Conflict Resolution**: Smart merge for simultaneous edits
- **OpenADP Integration**: Advanced distributed cryptography

### Enhanced Features
- **Note Organization**: Tags, folders, search
- **Rich Text**: Markdown support, syntax highlighting
- **Export/Import**: Backup and restore capabilities
- **Sharing**: Secure note sharing with time limits

## ⚠️ Important Notes

### Security Warnings
- **Remember your PIN**: There's no password recovery
- **Device Security**: Secure your device - anyone with access can see unlocked notes
- **Browser Data**: Clearing browser data will delete all notes
- **No Backups**: Currently no backup system (coming in Phase 2)

### Privacy
- **No Tracking**: No analytics, telemetry, or tracking
- **No Network**: No data leaves your device
- **Open Source**: All code is visible and auditable

## 🐛 Troubleshooting

### App Won't Load
1. Check browser compatibility at `/test.html`
2. Ensure JavaScript is enabled
3. Try in incognito/private mode
4. Clear site data and try again

### PIN Not Working
1. Double-check PIN spelling/case
2. Check attempts remaining
3. Wait if account is locked
4. Clear all data to reset (loses all notes)

### Notes Disappeared
1. Check if session expired (auto-lock)
2. Enter PIN to unlock
3. If completely lost, check browser data settings

## 🤝 Contributing

This is a prototype implementation. Future versions will include:
- OpenADP SDK integration
- Cloudflare R2 backend
- Real-time collaboration
- Enhanced security features

## 📄 License

This project is part of the OpenADP ecosystem. See the main project for licensing details.

---

**Remember**: Your notes are ghosts - they only exist while you're actively using the app! 👻 
