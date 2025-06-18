# Operation-Based Merge Algorithm

## Problem Statement

Content-addressable storage prevents some conflicts but doesn't handle operation conflicts:

```javascript
// Scenario: Two devices, same starting state
Initial: ["Buy milk"]

// Device A (offline): Edit "Buy milk" → "Buy organic milk"
Device A: ["Buy organic milk"]

// Device B (offline): Delete "Buy milk"  
Device B: []

// Sync conflict: Should final state be ["Buy organic milk"] or []?
```

## Solution: Operation Log with Vector Clocks

Track all operations with **vector clocks** to establish causal ordering and resolve conflicts deterministically.

### Data Structure

```javascript
const notesContainer = {
  version: 1,
  deviceId: "device-abc123",
  vectorClock: {
    "device-abc123": 5,  // This device's operation count
    "device-def456": 3,  // Other device's last known operation count
    "device-ghi789": 1   // Another device's last known operation count
  },
  operations: [
    {
      id: "op-uuid-1",
      type: "CREATE",
      contentHash: "hash-milk",
      content: "Buy milk",
      timestamp: 1705315800000,
      deviceId: "device-abc123",
      vectorClock: {"device-abc123": 1}
    },
    {
      id: "op-uuid-2", 
      type: "DELETE",
      contentHash: "hash-milk",
      content: "Buy milk",  // Store content for conflict resolution
      timestamp: 1705315900000,
      deviceId: "device-def456",
      vectorClock: {"device-abc123": 1, "device-def456": 1}
    },
    {
      id: "op-uuid-3",
      type: "EDIT",
      oldContentHash: "hash-milk",
      newContentHash: "hash-organic",
      oldContent: "Buy milk",
      newContent: "Buy organic milk",
      timestamp: 1705315850000,
      deviceId: "device-abc123", 
      vectorClock: {"device-abc123": 2, "device-def456": 1}
    }
  ],
  // Computed from operations - not stored
  notes: [/* derived state */]
};
```

## Merge Algorithm

### Step 1: Merge Operation Logs

```javascript
async function mergeOperationLogs(localContainer, cloudContainer) {
  // 1. Combine all operations from both devices
  const allOperations = [
    ...localContainer.operations,
    ...cloudContainer.operations
  ];
  
  // 2. Remove duplicates (same operation ID)
  const uniqueOperations = new Map();
  allOperations.forEach(op => {
    uniqueOperations.set(op.id, op);
  });
  
  // 3. Sort by vector clock causality, then timestamp
  const sortedOperations = Array.from(uniqueOperations.values())
    .sort((a, b) => {
      // If one operation causally precedes another, order by causality
      if (vectorClockLessThan(a.vectorClock, b.vectorClock)) return -1;
      if (vectorClockLessThan(b.vectorClock, a.vectorClock)) return 1;
      
      // If concurrent, order by timestamp, then device ID for determinism
      if (a.timestamp !== b.timestamp) return a.timestamp - b.timestamp;
      return a.deviceId.localeCompare(b.deviceId);
    });
  
  return sortedOperations;
}
```

### Step 2: Apply Operations with Conflict Resolution

```javascript
async function applyOperations(operations) {
  const noteStates = new Map(); // contentHash → {content, status: "ACTIVE"|"DELETED"}
  const conflicts = [];
  
  for (const operation of operations) {
    switch (operation.type) {
      case "CREATE":
        await applyCreate(operation, noteStates, conflicts);
        break;
      case "DELETE": 
        await applyDelete(operation, noteStates, conflicts);
        break;
      case "EDIT":
        await applyEdit(operation, noteStates, conflicts);
        break;
    }
  }
  
  // Return active notes only
  const activeNotes = [];
  for (const [contentHash, state] of noteStates) {
    if (state.status === "ACTIVE") {
      activeNotes.push({
        id: contentHash,
        content: state.content,
        created: state.created,
        deviceId: state.deviceId
      });
    }
  }
  
  return { notes: activeNotes, conflicts };
}
```

### Step 3: Conflict Resolution Rules

```javascript
async function applyCreate(operation, noteStates, conflicts) {
  const { contentHash, content } = operation;
  
  if (noteStates.has(contentHash)) {
    const existing = noteStates.get(contentHash);
    if (existing.status === "DELETED") {
      // CREATE after DELETE: Recreate the note
      noteStates.set(contentHash, {
        content,
        status: "ACTIVE",
        created: operation.timestamp,
        deviceId: operation.deviceId
      });
      conflicts.push({
        type: "CREATE_AFTER_DELETE",
        operation,
        resolution: "Note recreated"
      });
    }
    // CREATE on existing ACTIVE note: No-op (idempotent)
  } else {
    // Normal create
    noteStates.set(contentHash, {
      content,
      status: "ACTIVE", 
      created: operation.timestamp,
      deviceId: operation.deviceId
    });
  }
}

async function applyDelete(operation, noteStates, conflicts) {
  const { contentHash, content } = operation;
  
  if (noteStates.has(contentHash)) {
    const existing = noteStates.get(contentHash);
    if (existing.status === "ACTIVE") {
      // Normal delete
      noteStates.set(contentHash, {
        ...existing,
        status: "DELETED"
      });
    }
    // DELETE on already DELETED note: No-op (idempotent)
  } else {
    // DELETE on non-existent note: Create tombstone
    noteStates.set(contentHash, {
      content,
      status: "DELETED",
      created: operation.timestamp,
      deviceId: operation.deviceId
    });
    conflicts.push({
      type: "DELETE_NON_EXISTENT",
      operation,
      resolution: "Tombstone created"
    });
  }
}

async function applyEdit(operation, noteStates, conflicts) {
  const { oldContentHash, newContentHash, oldContent, newContent } = operation;
  
  // Check if old note exists and is active
  const oldNote = noteStates.get(oldContentHash);
  
  if (!oldNote || oldNote.status === "DELETED") {
    // EDIT on deleted/non-existent note: Treat as CREATE
    noteStates.set(newContentHash, {
      content: newContent,
      status: "ACTIVE",
      created: operation.timestamp,
      deviceId: operation.deviceId
    });
    conflicts.push({
      type: "EDIT_DELETED_NOTE",
      operation,
      resolution: "Treated as CREATE"
    });
    return;
  }
  
  // Normal edit: Delete old, create new
  noteStates.set(oldContentHash, {
    ...oldNote,
    status: "DELETED"
  });
  
  // Check if new content already exists
  if (noteStates.has(newContentHash)) {
    const existing = noteStates.get(newContentHash);
    if (existing.status === "DELETED") {
      // Edit to previously deleted content: Recreate
      noteStates.set(newContentHash, {
        content: newContent,
        status: "ACTIVE",
        created: operation.timestamp,
        deviceId: operation.deviceId
      });
    }
    // Edit to existing active content: No-op for new content
  } else {
    // Create new content
    noteStates.set(newContentHash, {
      content: newContent,
      status: "ACTIVE",
      created: operation.timestamp,
      deviceId: operation.deviceId
    });
  }
}
```

## Vector Clock Implementation

```javascript
function vectorClockLessThan(clockA, clockB) {
  // A < B if A[i] <= B[i] for all i, and A[j] < B[j] for some j
  let hasSmaller = false;
  
  const allDevices = new Set([...Object.keys(clockA), ...Object.keys(clockB)]);
  
  for (const device of allDevices) {
    const a = clockA[device] || 0;
    const b = clockB[device] || 0;
    
    if (a > b) return false; // A is not less than B
    if (a < b) hasSmaller = true;
  }
  
  return hasSmaller;
}

function incrementVectorClock(vectorClock, deviceId) {
  return {
    ...vectorClock,
    [deviceId]: (vectorClock[deviceId] || 0) + 1
  };
}

function mergeVectorClocks(clockA, clockB) {
  const allDevices = new Set([...Object.keys(clockA), ...Object.keys(clockB)]);
  const merged = {};
  
  for (const device of allDevices) {
    merged[device] = Math.max(clockA[device] || 0, clockB[device] || 0);
  }
  
  return merged;
}
```

## Conflict Scenarios & Resolutions

### Scenario 1: Edit vs Delete
```javascript
// Device A: EDIT "Buy milk" → "Buy organic milk"
// Device B: DELETE "Buy milk"

// Resolution: Both operations succeed
// - "Buy milk" is deleted
// - "Buy organic milk" is created (edit treated as CREATE)
// Result: ["Buy organic milk"]
```

### Scenario 2: Concurrent Edits
```javascript
// Device A: EDIT "Buy milk" → "Buy organic milk"  
// Device B: EDIT "Buy milk" → "Buy almond milk"

// Resolution: Both edits succeed
// - "Buy milk" is deleted
// - Both "Buy organic milk" and "Buy almond milk" are created
// Result: ["Buy organic milk", "Buy almond milk"]
```

### Scenario 3: Delete vs Delete
```javascript
// Device A: DELETE "Buy milk"
// Device B: DELETE "Buy milk"

// Resolution: Idempotent - single delete
// Result: []
```

### Scenario 4: Create after Delete
```javascript
// Device A: DELETE "Buy milk"
// Device B: CREATE "Buy milk" (later timestamp)

// Resolution: Note is recreated
// Result: ["Buy milk"]
```

### Scenario 5: Edit Non-existent Note
```javascript
// Device A: No operations
// Device B: EDIT "Buy milk" → "Buy organic milk" (but "Buy milk" never existed)

// Resolution: Treat as CREATE
// Result: ["Buy organic milk"]
```

## API Implementation

```javascript
// Create operation
async function addNote(content, pin, deviceId) {
  const container = await loadNotes(pin);
  const contentHash = await hashContent(content);
  
  // Check if note already exists
  const existingNote = container.notes.find(note => note.id === contentHash);
  if (existingNote) {
    return container; // No-op
  }
  
  // Create operation
  const operation = {
    id: generateOperationId(),
    type: "CREATE",
    contentHash,
    content: content.trim(),
    timestamp: Date.now(),
    deviceId,
    vectorClock: incrementVectorClock(container.vectorClock, deviceId)
  };
  
  const updatedContainer = {
    ...container,
    vectorClock: operation.vectorClock,
    operations: [...container.operations, operation]
  };
  
  // Recompute notes from operations
  const { notes } = await applyOperations(updatedContainer.operations);
  updatedContainer.notes = notes;
  
  await saveNotes(updatedContainer, pin);
  return updatedContainer;
}

// Edit operation  
async function editNote(oldContent, newContent, pin, deviceId) {
  const container = await loadNotes(pin);
  const oldContentHash = await hashContent(oldContent);
  const newContentHash = await hashContent(newContent);
  
  if (oldContentHash === newContentHash) {
    return container; // No change
  }
  
  const operation = {
    id: generateOperationId(),
    type: "EDIT",
    oldContentHash,
    newContentHash,
    oldContent: oldContent.trim(),
    newContent: newContent.trim(),
    timestamp: Date.now(),
    deviceId,
    vectorClock: incrementVectorClock(container.vectorClock, deviceId)
  };
  
  const updatedContainer = {
    ...container,
    vectorClock: operation.vectorClock,
    operations: [...container.operations, operation]
  };
  
  const { notes } = await applyOperations(updatedContainer.operations);
  updatedContainer.notes = notes;
  
  await saveNotes(updatedContainer, pin);
  return updatedContainer;
}

// Delete operation
async function deleteNote(content, pin, deviceId) {
  const container = await loadNotes(pin);
  const contentHash = await hashContent(content);
  
  const operation = {
    id: generateOperationId(),
    type: "DELETE",
    contentHash,
    content: content.trim(),
    timestamp: Date.now(),
    deviceId,
    vectorClock: incrementVectorClock(container.vectorClock, deviceId)
  };
  
  const updatedContainer = {
    ...container,
    vectorClock: operation.vectorClock,
    operations: [...container.operations, operation]
  };
  
  const { notes } = await applyOperations(updatedContainer.operations);
  updatedContainer.notes = notes;
  
  await saveNotes(updatedContainer, pin);
  return updatedContainer;
}
```

## Benefits

1. **Deterministic Merging**: Same operations always produce same result
2. **Conflict-Free**: All operations can coexist, conflicts resolved by rules
3. **Offline-First**: Operations recorded locally, merged on sync
4. **Audit Trail**: Complete history of all changes
5. **Causal Consistency**: Vector clocks ensure proper ordering

## Trade-offs

1. **Storage Overhead**: Must store operation log (can be compacted)
2. **Complexity**: More complex than simple content-addressable
3. **Merge Time**: O(n log n) where n = number of operations

This approach provides **strong eventual consistency** - all devices will converge to the same state given the same set of operations. 