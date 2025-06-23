# Ghost Notes: Session-Based Secure Notes App

## Overview
A notes application where notes are stored encrypted on the device and only decrypted during active sessions when the user provides their PIN. Uses OpenADP's distributed secret sharing for ultimate security.

## Core Concept
- **At Rest**: All notes encrypted and unreadable on device
- **Active Session**: Notes decrypted in memory only
- **Session End**: Memory cleared, notes remain encrypted
- **Limited Attempts**: User has MAX_GUESSES to enter correct PIN

## Architecture

### Data Flow
```
User PIN → OpenADP Recovery → Session Key → Decrypt Notes → In-Memory Storage
     ↓                                                            ↓
App Closes ← Clear Memory ← Re-encrypt ← Session Ends ← App Active
```

### Storage Strategy
```javascript
// On-disk storage (always encrypted)
{
  "note_id_1": {
    "encrypted_content": "...",
    "metadata": {
      "title_hash": "...",  // For searching without decryption
      "created": timestamp,
      "modified": timestamp,
      "tags_encrypted": "..."
    }
  },
  "app_metadata": {
    "user_id": "...",
    "server_list": [...],
    "guess_count": 3,
    "max_guesses": 10,
    "last_session": timestamp
  }
}

// In-memory during session (decrypted)
{
  "note_id_1": {
    "title": "My Secret Project",
    "content": "Full clear text content...",
    "tags": ["work", "confidential"],
    "created": timestamp,
    "modified": timestamp
  }
}
```

### Session Management
```javascript
class GhostNotesApp {
  constructor() {
    this.sessionKey = null;
    this.decryptedNotes = new Map();
    this.sessionActive = false;
    this.sessionTimer = null;
  }

  async startSession(userPIN) {
    // 1. Try to recover session key via OpenADP
    try {
      this.sessionKey = await this.recoverSessionKey(userPIN);
      
      // 2. Decrypt all notes into memory
      await this.decryptAllNotes();
      
      // 3. Start session
      this.sessionActive = true;
      this.setupSessionHandlers();
      
      return { success: true };
    } catch (error) {
      // Increment guess count
      await this.incrementGuessCount();
      return { success: false, error: error.message };
    }
  }

  async endSession() {
    // 1. Clear decrypted notes from memory
    this.decryptedNotes.clear();
    
    // 2. Clear session key
    this.sessionKey = null;
    
    // 3. Update encrypted storage with any changes
    await this.persistEncryptedNotes();
    
    // 4. Clear any sensitive data from memory
    this.sessionActive = false;
  }
}
```

## Key Features

### 1. PIN/Pattern Entry with Limited Attempts
```javascript
class PINEntry {
  async validatePIN(userInput) {
    const remainingGuesses = await this.getRemainingGuesses();
    
    if (remainingGuesses <= 0) {
      throw new Error('Account locked - too many failed attempts');
    }
    
    try {
      // Use OpenADP to validate PIN
      const sessionKey = await openadp.recoverSecret(userInput, this.servers);
      await this.resetGuessCount();
      return sessionKey;
    } catch (error) {
      await this.incrementGuessCount();
      const remaining = remainingGuesses - 1;
      throw new Error(`Invalid PIN. ${remaining} attempts remaining.`);
    }
  }
}
```

### 2. Note Management During Session
```javascript
class NotesManager {
  // Create new note (in memory during session)
  createNote(title, content, tags = []) {
    const note = {
      id: crypto.randomUUID(),
      title,
      content,
      tags,
      created: Date.now(),
      modified: Date.now()
    };
    
    this.decryptedNotes.set(note.id, note);
    this.markDirty(note.id);
    return note;
  }
  
  // Update existing note
  updateNote(noteId, updates) {
    const note = this.decryptedNotes.get(noteId);
    if (!note) throw new Error('Note not found');
    
    Object.assign(note, updates, { modified: Date.now() });
    this.markDirty(noteId);
    return note;
  }
  
  // Delete note
  deleteNote(noteId) {
    this.decryptedNotes.delete(noteId);
    this.markForDeletion(noteId);
  }
}
```

### 3. Auto-Lock Features
```javascript
class SessionSecurity {
  setupAutoLock() {
    // Lock on app backgrounding
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.scheduleAutoLock(5000); // 5 second grace period
      } else {
        this.cancelAutoLock();
      }
    });
    
    // Lock on inactivity
    let inactivityTimer;
    const resetInactivityTimer = () => {
      clearTimeout(inactivityTimer);
      inactivityTimer = setTimeout(() => {
        this.endSession();
      }, this.inactivityTimeout);
    };
    
    // Monitor user activity
    ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart']
      .forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
      });
  }
}
```

### 4. Encrypted Search & Metadata
```javascript
class EncryptedSearch {
  // Create searchable metadata without revealing content
  async createSearchableMetadata(note) {
    const sessionKey = this.getSessionKey();
    
    return {
      title_hash: await this.hashWithKey(note.title, sessionKey),
      tag_hashes: await Promise.all(
        note.tags.map(tag => this.hashWithKey(tag, sessionKey))
      ),
      content_snippet_hash: await this.hashWithKey(
        note.content.substring(0, 100), sessionKey
      )
    };
  }
  
  // Search encrypted notes
  async searchNotes(query) {
    const queryHash = await this.hashWithKey(query, this.getSessionKey());
    
    // Search through metadata hashes
    const matches = [];
    for (const [noteId, metadata] of this.encryptedMetadata) {
      if (metadata.title_hash === queryHash || 
          metadata.tag_hashes.includes(queryHash)) {
        matches.push(noteId);
      }
    }
    
    return matches;
  }
}
```

## User Interface Design

### 1. Login Screen
```html
<div class="ghost-login">
  <div class="ghost-logo">👻</div>
  <h1>Ghost Notes</h1>
  <div class="pin-entry">
    <input type="password" placeholder="Enter your PIN" />
    <div class="attempts-remaining">7 attempts remaining</div>
  </div>
  <button class="unlock-btn">Unlock Notes</button>
</div>
```

### 2. Main App Interface
```html
<div class="ghost-app">
  <header class="app-header">
    <h1>👻 Ghost Notes</h1>
    <div class="session-info">
      <div class="lock-timer">Auto-lock in 2:34</div>
      <button class="lock-now">🔒 Lock Now</button>
    </div>
  </header>
  
  <main class="notes-container">
    <div class="notes-list">
      <!-- Notes appear here during session -->
    </div>
    <div class="note-editor">
      <!-- Rich text editor -->
    </div>
  </main>
</div>
```

### 3. Session-End Warning
```html
<div class="ghost-warning">
  <div class="warning-icon">⚠️</div>
  <h2>Session Ending</h2>
  <p>Your notes will be encrypted and locked in 10 seconds...</p>
  <button class="extend-session">Stay Active</button>
</div>
```

## Settings & Configuration

```javascript
const ghostSettings = {
  maxGuesses: 10,           // User configurable
  autoLockTimeout: 300000,  // 5 minutes default
  sessionWarningTime: 30000, // 30 second warning
  servers: [               // OpenADP server list
    'https://server1.openadp.org',
    'https://server2.openadp.org',
    // ...
  ],
  threshold: 3,            // Need 3 servers for recovery
  gracePeriodOnBackground: 5000, // 5 seconds when app backgrounded
};
```

## Security Benefits

1. **Device Theft Protection**: Even with physical access, notes are encrypted
2. **Distributed Trust**: No single point of failure in key storage
3. **Limited Attempts**: Prevents brute force attacks
4. **Memory Isolation**: Clear text only exists during active sessions
5. **Auto-Lock**: Automatic protection on inactivity
6. **Recovery**: Can recover notes on new device with PIN

## Implementation Priority

### Phase 1: Core Functionality
- [ ] Basic session management (start/end)
- [ ] OpenADP integration for key recovery
- [ ] Simple note CRUD in memory
- [ ] Encrypted storage persistence
- [ ] PIN entry with attempt limiting

### Phase 2: Enhanced Security
- [ ] Auto-lock on inactivity/backgrounding
- [ ] Session warnings and extensions
- [ ] Secure memory clearing
- [ ] Settings management

### Phase 3: User Experience
- [ ] Rich text editing
- [ ] Note organization (tags, folders)
- [ ] Search functionality
- [ ] Import/export features
- [ ] Backup/restore workflows 