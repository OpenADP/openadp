# Private Notes - Security Analysis

## Single Encrypted Blob Architecture

### Security Rationale

The Private Notes demo uses a **single encrypted blob** containing all notes rather than encrypting each note individually. This design choice significantly enhances privacy by preventing metadata leakage.

## Metadata Leakage Prevention

### ❌ **Individual Encrypted Notes (Vulnerable)**

```javascript
// BAD: Each note is a separate encrypted blob
const storage = {
  "note-1": encrypt("My secret note", key),      // Reveals: note exists
  "note-2": encrypt("Shopping list", key),      // Reveals: note exists  
  "note-3": encrypt("Long diary entry...", key) // Reveals: note exists
};
```

**What attackers can learn WITHOUT decryption:**
- **Note count**: "User has exactly 3 notes"
- **Note sizes**: "Note 3 is much longer than notes 1 and 2"
- **Creation times**: "Note 2 was created after note 1"
- **Access patterns**: "User frequently modifies note 3"
- **Deletion patterns**: "User deleted a note last week"

### ✅ **Single Encrypted Blob (Secure)**

```javascript
// GOOD: All notes in one encrypted blob
const notesContainer = {
  notes: [
    { id: "note-1", content: "My secret note" },
    { id: "note-2", content: "Shopping list" },
    { id: "note-3", content: "Long diary entry..." }
  ],
  metadata: { count: 3, lastModified: Date.now() }
};

const storage = {
  "notes-blob": encrypt(JSON.stringify(notesContainer), key)
};
```

**What attackers can learn WITHOUT decryption:**
- **Nothing useful**: Only that user has "some notes"
- **No note count**: Could be 1 note or 1000 notes
- **No individual sizes**: All notes contribute to single blob size
- **No access patterns**: Any note access requires full blob decryption
- **No timing attacks**: All operations touch the same blob

## Threat Model Analysis

### Protected Against

#### 1. **Cloud Storage Breach**
```
Scenario: Cloudflare R2 gets hacked
Individual Notes: Attacker learns user has 47 notes, 
                 created over 6 months, with varying sizes
Single Blob:     Attacker learns user has "some encrypted data"
```

#### 2. **Database Analysis**
```
Scenario: Malware scans local storage
Individual Notes: Attacker maps user's note-taking patterns,
                 identifies important notes by size/access frequency
Single Blob:     Attacker sees single encrypted file, no patterns
```

#### 3. **Traffic Analysis**
```
Scenario: Network monitoring of sync operations
Individual Notes: Attacker tracks which specific notes are modified
Single Blob:     Attacker only sees "user updated their notes"
```

#### 4. **Forensic Analysis**
```
Scenario: Device seizure and forensic examination
Individual Notes: Investigator learns note count, sizes, timestamps
Single Blob:     Investigator learns only that notes exist
```

### Trade-offs and Considerations

#### Performance Impact
- **Read Operations**: Must decrypt entire blob to read any note
  - **Mitigation**: Cache decrypted data in memory during session
- **Write Operations**: Must encrypt entire blob to save any note
  - **Mitigation**: Batch writes, encrypt on background thread

#### Storage Efficiency
- **Space Overhead**: No per-note encryption overhead
- **Sync Efficiency**: Single blob upload/download vs. many small files
- **Compression**: JSON compresses well, reducing blob size

#### Implementation Complexity
- **Simpler Sync**: One blob to sync instead of complex conflict resolution
- **Atomic Operations**: All-or-nothing consistency guarantees
- **Version Control**: Single version number for entire note collection

## Implementation Security

### Key Derivation
```javascript
// Derive same key for entire blob
const key = await OpenADP.deriveKey({
  userPin: pin,
  appId: 'private-notes-demo',
  purpose: 'notes-encryption'
});
```

### Encryption Implementation
```javascript
// Encrypt entire notes container
async function encryptNotes(notesContainer, pin) {
  const key = await OpenADP.deriveKey(pin);
  const plaintext = JSON.stringify(notesContainer);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) },
    key,
    new TextEncoder().encode(plaintext)
  );
  return encrypted;
}
```

### Storage Security
```javascript
// Platform-specific secure storage
const storage = {
  // Linux PWA: IndexedDB (browser-managed encryption)
  web: () => indexedDB.put('notes-blob', encryptedBlob),
  
  // Android: Private app storage (Android encryption)
  android: () => writeFile('/data/data/app/files/notes.dat', encryptedBlob),
  
  // iOS: App sandbox (iOS encryption)
  ios: () => Data.write(to: documentsURL.appendingPathComponent('notes.dat'))
};
```

## Compliance and Privacy

### GDPR Compliance
- **Data Minimization**: Only encrypted blob stored, no metadata
- **Right to Erasure**: Delete single blob removes all user data
- **Privacy by Design**: Metadata protection built into architecture

### Zero-Knowledge Architecture
- **Server-Side**: OpenADP servers never see note content or metadata
- **Client-Side**: Only user's PIN can decrypt the blob
- **Cloud Storage**: Cloudflare R2 stores opaque encrypted blob

## Conclusion

The single encrypted blob architecture provides **significantly stronger privacy protection** than individual encrypted notes with minimal performance cost. This approach should be the standard for privacy-focused applications using OpenADP.

### Key Benefits Summary:
1. **🔒 Metadata Protection**: Prevents leakage of note count, sizes, and patterns
2. **🛡️ Forensic Resistance**: Minimal information available to investigators
3. **📊 Traffic Analysis Resistance**: No per-note sync patterns
4. **⚡ Implementation Simplicity**: Easier sync and conflict resolution
5. **🎯 Compliance Ready**: GDPR-friendly with data minimization 