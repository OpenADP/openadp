# 👻🔐 OpenADP Ghost Notes - Simple Version

A clean demonstration of the **OpenADP ocrypt APIs** that shows how to transform weak PIN security into military-grade protection.

## 🚀 Quick Start

1. **Start a local server** (required for ES6 modules):
   ```bash
   cd ghost-notes
   python3 -m http.server 8000
   ```

2. **Open in browser**:
   ```
   http://localhost:8000/index-openadp-simple.html
   ```

3. **Test the security transformation**:
   - Click "First Time Setup"
   - Enter any PIN (even "1234" works!)
   - See how OpenADP makes it cryptographically strong
   - Create notes and experience true "ghost" security

## 🔐 How It Works

This app demonstrates the **core value proposition** of OpenADP:

### Before OpenADP:
```javascript
// Traditional approach - VULNERABLE
const pin = "1234";  // Crackable in seconds
const hashed = bcrypt.hash(pin, 10);  // Still vulnerable to offline attacks
```

### With OpenADP:
```javascript
// OpenADP approach - SECURE  
const pin = "1234";  // Same PIN, but now protected!
const metadata = await register(userID, appID, secretData, pin, maxGuesses);
// PIN is now protected by distributed secret sharing across multiple servers
```

## 🛡️ Key Features Demonstrated

- **PIN Transformation**: Any PIN becomes cryptographically strong
- **Distributed Protection**: Secret split across multiple servers
- **Ghost Security**: Data only exists in memory during session
- **Automatic Backup Refresh**: OpenADP handles redundancy automatically
- **No Single Point of Failure**: Must compromise multiple servers to break

## 📝 Code Highlights

The entire security implementation uses just **2 API calls**:

### Setup (Protect notes with PIN):
```javascript
const metadata = await register(
    userID,         // User identifier  
    'ghost-notes',  // App identifier
    notesData,      // Secret data to protect
    pin,            // User's PIN
    10              // Max wrong attempts
);
```

### Unlock (Recover notes with PIN):
```javascript
const { secret, remaining, updatedMetadata } = await recover(metadata, pin);
const notesData = JSON.parse(new TextDecoder().decode(secret));
```

That's it! **Two lines of code** replace complex password hashing with distributed cryptography.

## 🎯 Perfect For

- **Secure note-taking** apps
- **Password managers** 
- **2FA backup codes**
- **Personal data vaults**
- **Any app** that needs to protect data with a PIN/password

## 🔍 Testing Tips

1. **Try weak PINs**: Use "1234" or "0000" - they're now secure!
2. **Test recovery**: Lock and unlock to see seamless experience
3. **Check the console**: Watch OpenADP work in real-time
4. **Experience ghost mode**: Data vanishes when locked

## 🚀 Production Ready

This demonstrates production-ready code patterns:

- ✅ Proper error handling with `OcryptError`
- ✅ Automatic metadata refresh
- ✅ Session management
- ✅ Memory cleanup on lock
- ✅ User-friendly experience

## 🌟 The Magic

**Same user experience. Vastly superior security.**

Your users get the convenience of simple PINs with the security of military-grade distributed cryptography. Even "1234" becomes practically unbreakable when protected by OpenADP's threshold cryptography across multiple servers.

---

*This is the power of the OpenADP ocrypt APIs - making nation-state resistant security as easy as bcrypt.* 