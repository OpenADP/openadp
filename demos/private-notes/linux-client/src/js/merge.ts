import type { 
    NotesContainer, 
    Operation, 
    CreateOperation, 
    DeleteOperation, 
    EditOperation,
    VectorClock,
    DeviceId,
    ContentHash,
    Timestamp
} from '../types/index.js';
import { 
    mergeVectorClocks, 
    compareVectorClocks, 
    areConcurrent 
} from './vector-clock.js';
import { 
    deriveNotesFromOperations,
    createNotesContainer 
} from './data-models.js';

/**
 * Operation-Based Merge Algorithm with Immediate Compaction
 * 
 * Implements conflict-free merging of operation logs from different devices
 * with immediate compaction to minimize storage and enhance privacy.
 */

/**
 * Result of merging two NotesContainers
 */
export interface MergeResult {
    readonly container: NotesContainer;
    readonly operationsAdded: number;
    readonly operationsRemoved: number;
    readonly conflictsResolved: number;
    readonly compacted: boolean;
}

/**
 * Merge two NotesContainers with immediate compaction
 * 
 * This is the main function for synchronizing notes between devices.
 * It handles all conflict scenarios and immediately compacts the result.
 */
export function mergeContainers(
    local: NotesContainer,
    remote: NotesContainer
): MergeResult {
    // Step 1: Merge vector clocks
    const mergedVectorClock = mergeVectorClocks(local.vectorClock, remote.vectorClock);
    
    // Step 2: Combine all operations from both containers
    const allOperations = [...local.operations, ...remote.operations];
    
    // Step 3: Remove duplicate operations (same operation ID)
    const uniqueOperations = deduplicateOperations(allOperations);
    
    // Step 4: Sort operations for deterministic processing
    const sortedOperations = sortOperationsForMerge(uniqueOperations);
    
    // Step 5: Apply conflict resolution rules
    const { resolvedOperations, conflictsResolved } = resolveConflicts(sortedOperations);
    
    // Step 6: Immediate compaction - convert to minimal CREATE operations
    const compactedOperations = compactOperations(resolvedOperations);
    
    // Step 7: Derive final notes state
    const finalNotes = deriveNotesFromOperations(compactedOperations);
    
    // Step 8: Create merged container
    const mergedContainer: NotesContainer = {
        version: Math.max(local.version, remote.version),
        deviceId: local.deviceId, // Keep local device ID
        vectorClock: mergedVectorClock,
        operations: compactedOperations,
        notes: finalNotes,
        lastCompacted: Date.now()
    } as const;
    
    const operationsAdded = remote.operations.length;
    const operationsRemoved = allOperations.length - compactedOperations.length;
    
    return {
        container: mergedContainer,
        operationsAdded,
        operationsRemoved,
        conflictsResolved,
        compacted: true
    } as const;
}

/**
 * Remove duplicate operations based on operation ID
 */
function deduplicateOperations(operations: readonly Operation[]): readonly Operation[] {
    const seen = new Set<string>();
    const unique: Operation[] = [];
    
    for (const operation of operations) {
        if (!seen.has(operation.id)) {
            seen.add(operation.id);
            unique.push(operation);
        }
    }
    
    return unique;
}

/**
 * Sort operations for deterministic merge processing
 * 
 * Primary sort: Vector clock ordering (causal order)
 * Secondary sort: Timestamp
 * Tertiary sort: Operation ID (for deterministic tie-breaking)
 */
function sortOperationsForMerge(operations: readonly Operation[]): readonly Operation[] {
    return [...operations].sort((a, b) => {
        // First try vector clock comparison
        const clockComparison = compareVectorClocks(a.vectorClock, b.vectorClock);
        
        if (clockComparison === 'before') return -1;
        if (clockComparison === 'after') return 1;
        
        // If concurrent or equal, sort by timestamp
        if (a.timestamp !== b.timestamp) {
            return a.timestamp - b.timestamp;
        }
        
        // Finally, sort by operation ID for deterministic ordering
        return a.id.localeCompare(b.id);
    });
}

/**
 * Conflict resolution result
 */
interface ConflictResolution {
    readonly resolvedOperations: readonly Operation[];
    readonly conflictsResolved: number;
}

/**
 * Apply conflict resolution rules to operations
 * 
 * Handles all conflict scenarios:
 * - Edit vs Delete: Both succeed (delete old, create new)
 * - Concurrent edits: Both succeed (delete old, create both new versions)
 * - Delete vs Delete: Idempotent
 * - Create after Delete: Note recreated
 * - Edit non-existent: Treat as CREATE
 */
function resolveConflicts(operations: readonly Operation[]): ConflictResolution {
    const resolved: Operation[] = [];
    let conflictsResolved = 0;
    
    // Track the current state of each content hash
    const contentState = new Map<ContentHash, {
        exists: boolean;
        lastOperation: Operation;
        conflictingOperations: Operation[];
    }>();
    
    // Process operations in sorted order
    for (const operation of operations) {
        switch (operation.type) {
            case 'CREATE': {
                const existing = contentState.get(operation.contentHash);
                
                if (!existing || !existing.exists) {
                    // Simple create - no conflict
                    contentState.set(operation.contentHash, {
                        exists: true,
                        lastOperation: operation,
                        conflictingOperations: []
                    });
                    resolved.push(operation);
                } else {
                    // Conflict: CREATE on existing content
                    // This can happen if the same content is created on different devices
                    // Keep the one with earlier timestamp (or earlier device ID for tie-breaking)
                    const current = existing.lastOperation;
                    if (operation.timestamp < current.timestamp || 
                        (operation.timestamp === current.timestamp && operation.deviceId < current.deviceId)) {
                        // Replace with earlier operation
                        const index = resolved.findIndex(op => op.id === current.id);
                        if (index >= 0) {
                            resolved[index] = operation;
                        }
                        existing.lastOperation = operation;
                        conflictsResolved++;
                    } else {
                        // Keep existing, ignore this CREATE
                        conflictsResolved++;
                    }
                }
                break;
            }
            
            case 'DELETE': {
                const existing = contentState.get(operation.contentHash);
                
                if (existing && existing.exists) {
                    // Delete existing note
                    existing.exists = false;
                    existing.lastOperation = operation;
                    resolved.push(operation);
                } else {
                    // Delete non-existent note - idempotent, just record it
                    contentState.set(operation.contentHash, {
                        exists: false,
                        lastOperation: operation,
                        conflictingOperations: []
                    });
                    resolved.push(operation);
                }
                break;
            }
            
            case 'EDIT': {
                const oldState = contentState.get(operation.oldContentHash);
                
                if (oldState && oldState.exists) {
                    // Edit existing note
                    // Remove old version
                    oldState.exists = false;
                    
                    // Add new version
                    contentState.set(operation.newContentHash, {
                        exists: true,
                        lastOperation: operation,
                        conflictingOperations: []
                    });
                    
                    resolved.push(operation);
                } else {
                    // Edit non-existent note - treat as CREATE
                    const createOp: CreateOperation = {
                        id: operation.id,
                        type: 'CREATE',
                        deviceId: operation.deviceId,
                        timestamp: operation.timestamp,
                        vectorClock: operation.vectorClock,
                        contentHash: operation.newContentHash,
                        content: operation.content
                    };
                    
                    contentState.set(operation.newContentHash, {
                        exists: true,
                        lastOperation: createOp,
                        conflictingOperations: []
                    });
                    
                    resolved.push(createOp);
                    conflictsResolved++;
                }
                break;
            }
        }
    }
    
    return {
        resolvedOperations: resolved,
        conflictsResolved
    };
}

/**
 * Compact operations to minimal CREATE operations
 * 
 * This is the key privacy and efficiency feature:
 * - Converts complex operation history to simple CREATE operations
 * - Reduces storage by 90%+
 * - Eliminates edit history for privacy
 * - Maintains all current notes
 */
function compactOperations(operations: readonly Operation[]): readonly Operation[] {
    // Derive the current notes state
    const currentNotes = deriveNotesFromOperations(operations);
    
    // Convert each current note to a simple CREATE operation
    const compactedOps: CreateOperation[] = currentNotes.map(note => ({
        id: `compact-${note.contentHash}-${Date.now()}`,
        type: 'CREATE' as const,
        deviceId: note.deviceId,
        timestamp: note.createdAt,
        vectorClock: {} as VectorClock, // Will be updated with latest vector clock
        contentHash: note.contentHash,
        content: note.content
    }));
    
    // Update vector clocks to reflect the latest state
    if (operations.length > 0) {
        const latestVectorClock = operations[operations.length - 1]?.vectorClock || {};
        compactedOps.forEach(op => {
            (op as any).vectorClock = latestVectorClock;
        });
    }
    
    return compactedOps;
}

/**
 * Check if two containers can be merged without conflicts
 */
export function canMergeWithoutConflicts(
    local: NotesContainer,
    remote: NotesContainer
): boolean {
    // If one container is a subset of the other's vector clock, no conflicts
    const localClock = local.vectorClock;
    const remoteClock = remote.vectorClock;
    
    const comparison = compareVectorClocks(localClock, remoteClock);
    return comparison === 'before' || comparison === 'after' || comparison === 'equal';
}

/**
 * Get merge preview without actually performing the merge
 */
export function previewMerge(
    local: NotesContainer,
    remote: NotesContainer
): {
    readonly newOperations: number;
    readonly potentialConflicts: number;
    readonly resultingNotes: number;
    readonly storageReduction: number;
} {
    const allOperations = [...local.operations, ...remote.operations];
    const uniqueOperations = deduplicateOperations(allOperations);
    const sortedOperations = sortOperationsForMerge(uniqueOperations);
    const { resolvedOperations, conflictsResolved } = resolveConflicts(sortedOperations);
    const compactedOperations = compactOperations(resolvedOperations);
    const finalNotes = deriveNotesFromOperations(compactedOperations);
    
    const newOperations = remote.operations.length;
    const storageReduction = Math.round(
        ((allOperations.length - compactedOperations.length) / allOperations.length) * 100
    );
    
    return {
        newOperations,
        potentialConflicts: conflictsResolved,
        resultingNotes: finalNotes.length,
        storageReduction
    } as const;
}

/**
 * Merge multiple containers (for syncing with multiple devices)
 */
export function mergeMultipleContainers(
    local: NotesContainer,
    remotes: readonly NotesContainer[]
): MergeResult {
    let current = local;
    let totalOperationsAdded = 0;
    let totalOperationsRemoved = 0;
    let totalConflictsResolved = 0;
    
    for (const remote of remotes) {
        const result = mergeContainers(current, remote);
        current = result.container;
        totalOperationsAdded += result.operationsAdded;
        totalOperationsRemoved += result.operationsRemoved;
        totalConflictsResolved += result.conflictsResolved;
    }
    
    return {
        container: current,
        operationsAdded: totalOperationsAdded,
        operationsRemoved: totalOperationsRemoved,
        conflictsResolved: totalConflictsResolved,
        compacted: true
    } as const;
}

/**
 * Validate that a merge result is consistent
 */
export function validateMergeResult(result: MergeResult): boolean {
    try {
        const { container } = result;
        
        // Check that all operations are CREATE operations (after compaction)
        const allCreates = container.operations.every(op => op.type === 'CREATE');
        if (!allCreates) {
            return false;
        }
        
        // Check that derived notes match stored notes
        const derivedNotes = deriveNotesFromOperations(container.operations);
        if (derivedNotes.length !== container.notes.length) {
            return false;
        }
        
        // Check that all notes have corresponding operations
        for (const note of container.notes) {
            const hasOperation = container.operations.some(
                op => op.type === 'CREATE' && op.contentHash === note.contentHash
            );
            if (!hasOperation) {
                return false;
            }
        }
        
        return true;
    } catch {
        return false;
    }
} 