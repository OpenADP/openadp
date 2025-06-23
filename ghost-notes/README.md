# 👻 Ghost Notes - OpenADP Protected

**Session-based secure note taking with distributed trust cryptography**

Ghost Notes is a privacy-focused note-taking application that protects your notes with OpenADP's distributed cryptography. Your notes are encrypted locally but the encryption keys are protected across multiple independent servers in different countries, making even simple PINs unbreakable by nation-states.

## ✨ Features

- 🛡️ **OpenADP Protection**: Distributed cryptography across multiple servers
- 🌍 **Nation-State Resistant**: Even simple PINs become unbreakable
- 🔐 **Local Encryption**: AES-GCM encryption with distributed key protection
- 👻 **Ghost Mode**: Notes vanish from memory when you're away
- 📱 **PWA Ready**: Install on phone/desktop like a native app
- 🔒 **Enhanced PIN Security**: PIN protected by threshold cryptography
- ⏱️ **Auto-Lock**: Automatic session timeout for security
- 📵 **Offline Capable**: Works without internet (after initial setup)

## 🛡️ Security Transformation

### Before OpenADP
- PIN "1234" = **Crackable in seconds**
- Single point of failure
- Vulnerable to government pressure

### With OpenADP
- PIN "1234" = **Unbreakable by nation-states**
- Distributed across multiple countries
- No single point of control or failure

## 🚀 Quick Start

### Local Testing

1. **Clone or download** the ghost-notes folder
2. **Start a local server**:
   ```bash
   cd ghost-notes
   python3 serve.py
   ```
3. **Open your browser** to `http://localhost:8080`
4. **Check OpenADP status** - should show "✅ OpenADP Network Connected"
5. **Create your first secure vault**

### First Time Setup

1. Click "⚙️ First Time Setup" on the login screen
2. **Learn about OpenADP**: Read the explanation of distributed cryptography
3. Create a PIN (even simple ones become secure with OpenADP)
4. Configure your security settings:
   - **Max Failed Attempts**: How many wrong PINs before lockout
   - **Auto-lock Timer**: How long until automatic lock
5. Click "🛡️ Create OpenADP Vault"
6. **Wait for registration**: OpenADP distributes your key across servers

### Daily Usage

1. **Unlock**: Enter your PIN (protected by distributed cryptography)
2. **Create Notes**: Click ➕ to add new notes
3. **Edit**: Click any note to edit title and content
4. **Auto-Save**: Changes save automatically as you type
5. **Lock**: Notes are secured with OpenADP when you close or walk away

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

### OpenADP Distributed Cryptography
- **Threshold Cryptography**: Your encryption key is split across multiple servers
- **Geographic Distribution**: Servers in different countries and jurisdictions
- **No Single Point of Failure**: Multiple servers must cooperate to access data
- **Government Resistant**: No single authority can force access

### Local Encryption
- **Algorithm**: AES-GCM 256-bit encryption
- **Key Protection**: Encryption keys protected by OpenADP network
- **IV**: Random initialization vector per encryption
- **Metadata**: Only safe metadata stored locally

### Session Management
- **PIN Authentication**: Required for every session
- **Distributed Verification**: PIN verified through OpenADP network
- **Failed Attempt Limiting**: Configurable lockout protection
- **Auto-Lock**: Inactivity timeout with warning
- **Memory Clearing**: Notes purged from RAM when locked

### Network Architecture
- **OpenADP Servers**: Multiple independent servers protect your keys
- **Health Monitoring**: Real-time network status checking
- **Automatic Failover**: System works even if some servers are down
- **Transparent Operation**: All complexity hidden from user

## 🛠️ Technical Details

### Browser Requirements
- Modern browser with Web Crypto API support
- Fetch API support for OpenADP communication
- localStorage support for metadata
- Service Worker support (for PWA features)

### OpenADP Integration
- **SDK**: Uses OpenADP JavaScript SDK
- **Ocrypt API**: High-level distributed cryptography interface
- **Network Health**: Monitors server connectivity
- **Error Handling**: Graceful degradation for network issues

### File Structure
```
ghost-notes/
├── index.html          # Main app with OpenADP UI
├── app.js             # Application logic with Ocrypt integration
├── styles.css         # Dark theme with OpenADP styling
├── manifest.json      # PWA manifest
├── sw.js             # Service worker
├── serve.py          # Local development server
└── README.md         # This file
```

## 🌐 OpenADP Network

### Server Distribution
- **Multiple Countries**: Servers in different jurisdictions
- **Independent Operators**: No single entity controls all servers
- **Health Monitoring**: Real-time status at https://health.openadp.org
- **Transparency**: Open source and auditable

### How It Works
1. **Registration**: Your PIN creates key shares distributed to servers
2. **Recovery**: Multiple servers must cooperate to reconstruct keys
3. **Threshold Security**: System works even if some servers fail
4. **Geographic Diversity**: International distribution prevents single-point pressure

## ⚠️ Important Notes

### Security Features
- **Enhanced PIN Protection**: Even "1234" becomes secure with OpenADP
- **Device Security**: Still secure your device - physical access matters
- **Network Dependency**: Initial setup requires internet for OpenADP registration
- **Distributed Backup**: Your keys are automatically backed up across servers

### Privacy Guarantees
- **No Data Transmission**: Only encrypted metadata leaves your device
- **Zero Knowledge**: OpenADP servers cannot see your notes
- **Open Source**: All code is visible and auditable
- **No Tracking**: No analytics, telemetry, or tracking

### Network Requirements
- **Initial Setup**: Internet required for OpenADP registration
- **Daily Use**: Works offline after setup
- **Recovery**: Internet required to unlock notes
- **Sync**: Future versions will support cross-device sync

## 🐛 Troubleshooting

### OpenADP Connection Issues
1. Check network status indicator on login screen
2. Visit https://health.openadp.org to verify network status
3. Try again in a few minutes if servers are temporarily down
4. Check your internet connection

### App Won't Load
1. Ensure internet connection for OpenADP communication
2. Check browser compatibility
3. Ensure JavaScript is enabled
4. Try in incognito/private mode

### PIN Not Working
1. Double-check PIN spelling/case
2. Check attempts remaining
3. Wait if account is locked
4. Verify OpenADP network is accessible

### Notes Disappeared
1. Check if session expired (auto-lock)
2. Enter PIN to unlock via OpenADP
3. Verify OpenADP network connectivity
4. Check browser data settings for metadata

## 🔮 Future Enhancements

### Advanced OpenADP Features
- **Cross-Device Sync**: Sync encrypted notes across devices
- **Collaborative Editing**: Real-time multi-user editing with OpenADP
- **Enhanced Recovery**: Multiple recovery methods with distributed trust
- **Policy Enforcement**: Configurable security policies

### Enhanced Features
- **Note Organization**: Tags, folders, search
- **Rich Text**: Markdown support, syntax highlighting
- **Export/Import**: Secure backup and restore capabilities
- **Sharing**: Secure note sharing with distributed access control

## 🤝 Contributing

Ghost Notes is part of the OpenADP ecosystem demonstrating real-world distributed cryptography applications. Contributions welcome for:

- UI/UX improvements
- Additional security features
- Performance optimizations
- Cross-platform compatibility

## 📄 License

This project is part of the OpenADP ecosystem. See the main project for licensing details.

---

**🛡️ Your notes are protected by distributed trust cryptography across multiple countries. Even simple PINs become unbreakable by nation-states!** 👻 
