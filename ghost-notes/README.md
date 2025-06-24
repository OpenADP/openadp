# 👻 Ghost Notes

**Session-based secure note taking app - your notes vanish when you leave**

Ghost Notes is a privacy-focused note-taking application that keeps your notes encrypted and only accessible during active sessions. When you close the app or walk away, your notes disappear like ghosts until you unlock them again.

## ✨ Features

- 🔐 **OpenADP Protection**: Nation-state resistant distributed cryptography replaces PBKDF2
- 👻 **Ghost Mode**: Notes vanish from memory when you're away
- 📱 **PWA Ready**: Install on phone/desktop like a native app
- 🔒 **PIN Protection**: Strong PIN-based authentication
- ⏱️ **Auto-Lock**: Automatic session timeout for security
- 🚫 **No Cloud**: Everything stays on your device (for now)
- 📵 **Offline First**: Works without internet connection

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

## 🔒 Security Features

### Encryption
- **Algorithm**: AES-GCM 256-bit encryption
- **Key Protection**: OpenADP distributed threshold cryptography with automatic backup refresh
- **Random Salt**: Unique per installation
- **IV**: Random initialization vector per encryption

### Session Management
- **PIN Authentication**: Required for every session
- **Failed Attempt Limiting**: Configurable lockout protection
- **Auto-Lock**: Inactivity timeout with warning
- **Memory Clearing**: Notes purged from RAM when locked

### Storage
- **Local Only**: Everything stored in browser localStorage
- **No Network**: No data transmitted anywhere (yet)
- **Encrypted at Rest**: Notes never stored in plain text

## 🛠️ Technical Details

### Browser Requirements
- Modern browser with Web Crypto API support
- localStorage support
- Service Worker support (for PWA features)

### File Structure
```
ghost-notes/
├── index.html          # Main app
├── app.js             # Application logic
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