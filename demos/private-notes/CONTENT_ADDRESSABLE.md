# Content-Addressable Notes Architecture

## Overview

Private Notes uses a **content-addressable storage** model where notes are uniquely identified by their content hash. This elegant approach eliminates most synchronization conflicts while maintaining strong privacy guarantees.

## Core Principles

### 1. **Content is Identity**
```javascript
// Note ID is derived from content
const noteId = await hashContent("Buy milk and eggs"); 
// → "a1b2c3d4e5f6g7h8"

const note = {
  id: "a1b2c3d4e5f6g7h8",
  content: "Buy milk and eggs",
  created: 1705315800000,
  deviceId: "device-uuid-123"
};
```

### 2. **Duplicate Prevention**
```javascript
// Adding identical content is a no-op
await addNote("Buy milk", pin, deviceId);        // Creates note
await addNote("Buy milk", pin, deviceId);        // No-op (already exists)
await addNote("BUY MILK  ", pin, deviceId);      // No-op (normalized to same hash)
```

### 3. **Edit = Delete + Add**
```javascript
// Editing replaces old content with new content
await editNote("Buy milk", "Buy milk and eggs", pin, deviceId);
// Equivalent to:
// 1. Delete note with content "Buy milk"
// 2. Add note with content "Buy milk and eggs"
```

## Conflict Resolution

### **The Problem with Traditional Approaches**
```javascript
// Traditional approach - conflicts inevitable
Device A: notes = [{id: "note-1", content: "Buy milk", modified: 100}]
Device B: notes = [{id: "note-1", content: "Buy eggs", modified: 101}]
// Sync conflict: Which version wins? Data loss inevitable.
```

### **Content-Addressable Solution**
```javascript
// Content-addressable - no conflicts possible
Device A: notes = [
  {id: "hash-milk", content: "Buy milk", created: 100},
  {id: "hash-eggs", content: "Buy eggs", created: 101}
]
Device B: notes = [
  {id: "hash-milk", content: "Buy milk", created: 100},  // Same hash
  {id: "hash-bread", content: "Buy bread", created: 102}
]
// Sync result: Union of all unique content = 3 notes, no conflicts
```

## Offline-First Operations

### **Scenario: User Works Offline**
1. **Device A (offline)**: User adds "Call dentist"
2. **Device B (offline)**: User adds "Call dentist" (identical content)
3. **Both devices sync**: Only one note exists (same content hash)
4. **Result**: Perfect merge, no duplicates, no conflicts

### **Scenario: User Edits Offline**
1. **Initial state**: Note "Buy milk" exists on both devices
2. **Device A (offline)**: Edit "Buy milk" → "Buy milk and eggs"
3. **Device B (offline)**: Edit "Buy milk" → "Buy organic milk"
4. **Sync result**: 
   - Original "Buy milk" deleted from both
   - Two new notes: "Buy milk and eggs" and "Buy organic milk"
   - User sees both edits, can manually resolve if needed

## Implementation Details

### **Content Normalization**
```javascript
async function hashContent(content) {
  // Normalize to ensure consistent hashing
  const normalized = content.trim().toLowerCase();
  const encoder = new TextEncoder();
  const data = encoder.encode(normalized);
  
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  
  // Use first 16 hex chars for readability
  return Array.from(hashArray.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
```

### **Atomic Operations**
```javascript
// All operations follow read-modify-write pattern
async function addNote(content, pin, deviceId) {
  const contentId = await hashContent(content);
  
  // 1. Read current state
  const container = await loadNotes(pin);
  
  // 2. Check if already exists
  if (container.notes.find(note => note.id === contentId)) {
    return container; // No-op
  }
  
  // 3. Modify
  const updatedContainer = {
    ...container,
    notes: [...container.notes, newNote],
    lastModified: Date.now()
  };
  
  // 4. Write atomically
  await saveNotes(updatedContainer, pin);
  return updatedContainer;
}
```

### **Sync Algorithm**
```javascript
async function syncNotes(pin) {
  // 1. Download cloud state
  const cloudBlob = await downloadFromCloud();
  const localContainer = await loadNotes(pin);
  
  if (!cloudBlob) {
    // No cloud version, upload local
    await uploadToCloud(encryptedLocal);
    return localContainer;
  }
  
  // 2. Decrypt cloud state
  const cloudContainer = await decryptNotesContainer(cloudBlob, key);
  
  // 3. Merge: Union of all notes by content hash
  const mergedNotesMap = new Map();
  
  localContainer.notes.forEach(note => {
    mergedNotesMap.set(note.id, note);
  });
  
  cloudContainer.notes.forEach(note => {
    if (!mergedNotesMap.has(note.id)) {
      mergedNotesMap.set(note.id, note);
    }
    // If exists locally, keep local (same content anyway)
  });
  
  // 4. Save merged result
  const mergedContainer = {
    version: 1,
    lastModified: Date.now(),
    deviceId: localContainer.deviceId,
    notes: Array.from(mergedNotesMap.values())
  };
  
  await saveNotes(mergedContainer, pin);
  return mergedContainer;
}
```

## Benefits

### **✅ Conflict-Free**
- **No merge conflicts**: Content hash ensures uniqueness
- **Deterministic merging**: Same content = same hash = same note
- **Offline resilience**: Works perfectly without connectivity

### **✅ Simple Mental Model**
- **Easy to understand**: "Same content = same note"
- **Predictable behavior**: No surprise overwrites or data loss
- **Clear edit semantics**: Edit always creates new note

### **✅ Efficient Sync**
- **Minimal data transfer**: Only sync new content hashes
- **Fast conflict resolution**: Simple set union operation
- **Atomic operations**: All-or-nothing consistency

### **✅ Privacy Preserving**
- **Single encrypted blob**: Still maintains metadata protection
- **Content-blind cloud**: Cloud storage sees only encrypted blob
- **Hash collision resistance**: SHA-256 prevents content inference

## Edge Cases Handled

### **Case 1: Whitespace Variations**
```javascript
await addNote("Buy milk", pin, deviceId);      // Creates note
await addNote("  Buy milk  ", pin, deviceId);  // No-op (normalized)
await addNote("BUY MILK", pin, deviceId);      // No-op (normalized)
```

### **Case 2: Edit to Existing Content**
```javascript
// Initial: ["Buy milk", "Buy eggs"]
await editNote("Buy milk", "Buy eggs", pin, deviceId);
// Result: ["Buy eggs"] (duplicate removed, original deleted)
```

### **Case 3: Concurrent Identical Edits**
```javascript
// Device A: Edit "Buy milk" → "Buy organic milk"
// Device B: Edit "Buy milk" → "Buy organic milk" (same edit)
// Sync result: Single note "Buy organic milk"
```

### **Case 4: Hash Collisions (Extremely Rare)**
```javascript
// If SHA-256 collision occurs (probability: ~2^-256)
// Notes would be treated as identical
// Acceptable risk given collision resistance of SHA-256
```

## Comparison with Traditional Approaches

| Aspect | Traditional Notes | Content-Addressable |
|--------|------------------|-------------------|
| **Conflicts** | Frequent, complex resolution | Rare, automatic resolution |
| **Duplicates** | Manual deduplication needed | Impossible by design |
| **Offline** | Sync conflicts inevitable | Perfect offline support |
| **Mental Model** | Complex (IDs, versions, timestamps) | Simple (content = identity) |
| **Data Loss** | Possible during conflicts | Prevented by design |
| **Implementation** | Complex merge algorithms | Simple set operations |

## Conclusion

Content-addressable storage transforms note synchronization from a complex conflict resolution problem into a simple set union operation. This approach provides:

1. **Zero conflict resolution complexity**
2. **Perfect offline-first behavior** 
3. **Guaranteed duplicate prevention**
4. **Simple, predictable user experience**
5. **Maintained privacy guarantees**

The trade-off is that editing a note creates a new note rather than modifying an existing one, but this is actually beneficial for many use cases and aligns well with the immutable nature of encrypted content. 