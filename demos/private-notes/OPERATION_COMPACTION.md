# Operation Log Compaction Strategy

## Why Compact After Every Merge?

For a private notes app with small data volumes, **aggressive compaction** provides significant benefits with minimal downsides.

### Benefits of Immediate Compaction

#### 1. **Minimal Storage Overhead**
```javascript
// Before compaction (after many edits):
operations: [
  {type: "CREATE", contentHash: "hash-milk", content: "Buy milk"},
  {type: "EDIT", oldHash: "hash-milk", newHash: "hash-organic", ...},
  {type: "EDIT", oldHash: "hash-organic", newHash: "hash-oat", ...},
  {type: "DELETE", contentHash: "hash-oat"},
  {type: "CREATE", contentHash: "hash-bread", content: "Buy bread"},
  // ... 50+ operations for simple note changes
]

// After compaction:
operations: [
  {type: "CREATE", contentHash: "hash-bread", content: "Buy bread"}
]
// Storage reduced by 98%!
```

#### 2. **Faster Sync Operations**
- **Smaller encrypted blobs**: Less data to encrypt/decrypt/transfer
- **Faster merge**: Fewer operations to process
- **Reduced bandwidth**: Minimal cloud storage usage

#### 3. **Privacy Enhancement**
- **Less metadata**: Shorter operation history reduces analysis surface
- **Simpler patterns**: Harder to infer user behavior from compact logs

#### 4. **Simplified Debugging**
- **Clean state**: Each sync produces minimal, canonical operation log
- **Easier reasoning**: Current state directly visible in operations

### Compaction Algorithm

```javascript
async function compactOperationLog(operations) {
  // 1. Apply all operations to get final state
  const { notes } = await applyOperations(operations);
  
  // 2. Generate minimal CREATE operations for current state
  const compactedOps = notes.map(note => ({
    id: generateOperationId(),
    type: "CREATE",
    contentHash: note.id,
    content: note.content,
    timestamp: note.created,
    deviceId: note.deviceId,
    vectorClock: {} // Reset vector clock after compaction
  }));
  
  // 3. Update vector clock to reflect compaction
  const maxClock = getMaxVectorClock(operations);
  const compactionClock = incrementAllDevices(maxClock);
  
  return {
    operations: compactedOps,
    vectorClock: compactionClock,
    compactedAt: Date.now(),
    originalOpCount: operations.length
  };
}

function getMaxVectorClock(operations) {
  const maxClock = {};
  
  operations.forEach(op => {
    Object.entries(op.vectorClock).forEach(([device, count]) => {
      maxClock[device] = Math.max(maxClock[device] || 0, count);
    });
  });
  
  return maxClock;
}

function incrementAllDevices(vectorClock) {
  const incremented = {};
  Object.entries(vectorClock).forEach(([device, count]) => {
    incremented[device] = count + 1; // Increment to mark compaction
  });
  return incremented;
}
```

### Integration with Sync Process

```javascript
async function syncNotesWithCompaction(pin, deviceId) {
  // 1. Standard merge process
  const localContainer = await loadNotes(pin);
  const cloudBlob = await downloadFromCloud();
  
  if (!cloudBlob) {
    // No cloud version - compact local and upload
    const compacted = await compactOperationLog(localContainer.operations);
    const finalContainer = {
      ...localContainer,
      ...compacted
    };
    
    await saveNotes(finalContainer, pin);
    await uploadToCloud(await encryptNotesContainer(finalContainer, key, deviceId));
    return finalContainer;
  }
  
  // 2. Merge with cloud
  const { notesContainer: cloudContainer } = await decryptNotesContainer(cloudBlob, key);
  const allOperations = mergeOperationLogs(localContainer, cloudContainer);
  
  // 3. Apply operations
  const { notes, conflicts } = await applyOperations(allOperations);
  
  // 4. COMPACT IMMEDIATELY after merge
  const compacted = await compactOperationLog(allOperations);
  
  const finalContainer = {
    version: 1,
    deviceId: localContainer.deviceId,
    vectorClock: compacted.vectorClock,
    operations: compacted.operations,
    notes: notes,
    lastCompacted: compacted.compactedAt,
    compactionStats: {
      originalOpCount: compacted.originalOpCount,
      compactedOpCount: compacted.operations.length,
      reductionPercent: Math.round((1 - compacted.operations.length / compacted.originalOpCount) * 100)
    }
  };
  
  // 5. Save compacted result locally and to cloud
  await saveNotes(finalContainer, pin);
  await uploadToCloud(await encryptNotesContainer(finalContainer, key, deviceId));
  
  console.log(`Compacted ${compacted.originalOpCount} operations to ${compacted.operations.length} (${finalContainer.compactionStats.reductionPercent}% reduction)`);
  
  return finalContainer;
}
```

### Vector Clock Handling After Compaction

```javascript
// Problem: After compaction, vector clocks are reset
// Solution: Use compaction markers

const compactedContainer = {
  vectorClock: {
    "device-abc": 15,  // Incremented after compaction
    "device-def": 8,   // Incremented after compaction  
    "device-ghi": 3    // Incremented after compaction
  },
  compactionGeneration: 1,  // Track compaction cycles
  operations: [
    // Only CREATE operations for current state
    {
      id: "create-post-compact-1",
      type: "CREATE", 
      contentHash: "hash-bread",
      content: "Buy bread",
      timestamp: 1705315800000,
      deviceId: "device-abc",
      vectorClock: {"device-abc": 15}, // Post-compaction clock
      isCompacted: true  // Mark as post-compaction operation
    }
  ]
};
```

### Handling Cross-Device Compaction

```javascript
async function mergeWithCompactedDevices(localOps, cloudOps) {
  // Check if either side has been compacted
  const localCompacted = localOps.some(op => op.isCompacted);
  const cloudCompacted = cloudOps.some(op => op.isCompacted);
  
  if (localCompacted && cloudCompacted) {
    // Both sides compacted - simple merge of CREATE operations
    return simpleMergeCompacted(localOps, cloudOps);
  } else if (localCompacted || cloudCompacted) {
    // One side compacted - need careful merge
    return mergeCompactedWithUncompacted(localOps, cloudOps);
  } else {
    // Neither side compacted - standard merge
    return standardMerge(localOps, cloudOps);
  }
}

function simpleMergeCompacted(localOps, cloudOps) {
  // Both sides are compacted CREATE operations
  // Simple union by content hash
  const mergedNotes = new Map();
  
  [...localOps, ...cloudOps].forEach(op => {
    if (op.type === "CREATE") {
      // Keep the operation with latest timestamp for each content
      const existing = mergedNotes.get(op.contentHash);
      if (!existing || op.timestamp > existing.timestamp) {
        mergedNotes.set(op.contentHash, op);
      }
    }
  });
  
  return Array.from(mergedNotes.values());
}
```

## Trade-offs Analysis

### ✅ **Pros of Aggressive Compaction**

1. **Storage Efficiency**: 90%+ reduction in operation log size
2. **Sync Performance**: Faster encryption, transfer, and merge
3. **Privacy**: Less historical metadata exposed
4. **Simplicity**: Clean state after every sync
5. **Cost**: Lower cloud storage costs
6. **Battery**: Less CPU/network usage on mobile

### ⚠️ **Potential Cons (Minimal for Notes App)**

1. **Lost History**: Can't see edit history (acceptable for notes)
2. **Debugging**: Less audit trail (logs can capture important events)
3. **Conflict Analysis**: Can't analyze historical conflicts (rarely needed)
4. **Undo Operations**: Can't undo across sync boundaries (acceptable)

### 🎯 **Perfect for Notes App Because:**

- **Small Data**: Notes are typically < 1KB each
- **Simple Operations**: Create/edit/delete are straightforward
- **Infrequent Conflicts**: Users rarely edit same note simultaneously
- **Privacy Focus**: Less metadata is better
- **Mobile Usage**: Battery and bandwidth matter

## Implementation Strategy

### Phase 1: Basic Compaction
```javascript
// Compact after every successful sync
async function syncNotes(pin, deviceId) {
  const merged = await performMerge(pin);
  const compacted = await compactOperationLog(merged.operations);
  return await saveFinalState(compacted);
}
```

### Phase 2: Smart Compaction (Future)
```javascript
// Compact based on thresholds (if needed later)
async function smartCompaction(operations) {
  if (operations.length > 100 || 
      getStorageSize(operations) > 10000 || 
      timeSinceLastCompaction() > 24 * 60 * 60 * 1000) {
    return await compactOperationLog(operations);
  }
  return operations;
}
```

## Conclusion

For Private Notes, **compacting after every merge** is optimal:

1. **Dramatic storage savings** (90%+ reduction)
2. **Faster sync performance** 
3. **Enhanced privacy** (less metadata)
4. **Simplified debugging**
5. **Lower costs** (storage, bandwidth, battery)

The downsides (lost edit history, reduced audit trail) are minimal for a personal notes application where current state matters more than historical changes.

**Recommendation**: Implement aggressive compaction from day one. The benefits far outweigh the costs for this use case. 