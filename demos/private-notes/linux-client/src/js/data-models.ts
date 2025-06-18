import type { 
    NotesContainer, 
    Operation, 
    CreateOperation, 
    DeleteOperation, 
    EditOperation,
    Note,
    DeviceId,
    ContentHash,
    OperationId,
    Timestamp,
    VectorClock
} from '../types/index.js';
import { v4 as uuidv4 } from 'uuid';
import { hashContent } from '../../shared/crypto-utils.js';
import { createVectorClock, incrementVectorClock } from './vector-clock.js';

/**
 * Data Models Implementation for Private Notes
 * 
 * Provides factory functions and utilities for creating and managing
 * the core data structures used in the operation-based notes system.
 */

/**
 * Generate a unique device ID for this browser/device
 */
export function generateDeviceId(): DeviceId {
    // Check if we already have a device ID stored
    const stored = localStorage.getItem('openadp-device-id');
    if (stored) {
        return stored;
    }
    
    // Generate new device ID and store it
    const deviceId = `device-${uuidv4()}`;
    localStorage.setItem('openadp-device-id', deviceId);
    return deviceId;
}

/**
 * Get the current device ID
 */
export function getDeviceId(): DeviceId {
    return generateDeviceId(); // Will return existing or create new
}

/**
 * Create a new empty NotesContainer for a device
 */
export function createNotesContainer(deviceId: DeviceId): NotesContainer {
    return {
        version: 1,
        deviceId,
        vectorClock: createVectorClock(deviceId),
        operations: [],
        notes: [],
        lastCompacted: Date.now()
    } as const;
}

/**
 * Create a CREATE operation for a new note
 */
export async function createCreateOperation(
    content: string,
    deviceId: DeviceId,
    vectorClock: VectorClock
): Promise<CreateOperation> {
    const contentHash = await hashContent(content);
    const newVectorClock = incrementVectorClock(vectorClock, deviceId);
    
    return {
        id: `op-${uuidv4()}`,
        type: 'CREATE',
        deviceId,
        timestamp: Date.now(),
        vectorClock: newVectorClock,
        contentHash,
        content
    } as const;
}

/**
 * Create a DELETE operation for an existing note
 */
export function createDeleteOperation(
    contentHash: ContentHash,
    deviceId: DeviceId,
    vectorClock: VectorClock
): DeleteOperation {
    const newVectorClock = incrementVectorClock(vectorClock, deviceId);
    
    return {
        id: `op-${uuidv4()}`,
        type: 'DELETE',
        deviceId,
        timestamp: Date.now(),
        vectorClock: newVectorClock,
        contentHash
    } as const;
}

/**
 * Create an EDIT operation for modifying an existing note
 */
export async function createEditOperation(
    oldContentHash: ContentHash,
    newContent: string,
    deviceId: DeviceId,
    vectorClock: VectorClock
): Promise<EditOperation> {
    const newContentHash = await hashContent(newContent);
    const newVectorClock = incrementVectorClock(vectorClock, deviceId);
    
    return {
        id: `op-${uuidv4()}`,
        type: 'EDIT',
        deviceId,
        timestamp: Date.now(),
        vectorClock: newVectorClock,
        oldContentHash,
        newContentHash,
        content: newContent
    } as const;
}

/**
 * Create a Note from a CREATE operation
 */
export function createNoteFromOperation(operation: CreateOperation): Note {
    return {
        contentHash: operation.contentHash,
        content: operation.content,
        createdAt: operation.timestamp,
        updatedAt: operation.timestamp,
        deviceId: operation.deviceId
    } as const;
}

/**
 * Update a Note from an EDIT operation
 */
export function updateNoteFromOperation(note: Note, operation: EditOperation): Note {
    return {
        ...note,
        contentHash: operation.newContentHash,
        content: operation.content,
        updatedAt: operation.timestamp
    } as const;
}

/**
 * Derive the current notes state from a list of operations
 * This is the core function that computes the current state from the operation log
 */
export function deriveNotesFromOperations(operations: readonly Operation[]): readonly Note[] {
    // Sort operations by vector clock for deterministic processing
    const sortedOps = [...operations].sort((a, b) => {
        // First sort by timestamp as a rough ordering
        if (a.timestamp !== b.timestamp) {
            return a.timestamp - b.timestamp;
        }
        // Then by operation ID for deterministic tie-breaking
        return a.id.localeCompare(b.id);
    });
    
    // Map to track current notes by content hash
    const notesByHash = new Map<ContentHash, Note>();
    
    // Process each operation in order
    for (const operation of sortedOps) {
        switch (operation.type) {
            case 'CREATE': {
                // Create a new note (or recreate if it was deleted)
                const note = createNoteFromOperation(operation);
                notesByHash.set(operation.contentHash, note);
                break;
            }
            
            case 'DELETE': {
                // Remove the note if it exists
                notesByHash.delete(operation.contentHash);
                break;
            }
            
            case 'EDIT': {
                // Find the old note and update it
                const oldNote = notesByHash.get(operation.oldContentHash);
                if (oldNote) {
                    // Remove old version and add new version
                    notesByHash.delete(operation.oldContentHash);
                    const updatedNote = updateNoteFromOperation(oldNote, operation);
                    notesByHash.set(operation.newContentHash, updatedNote);
                }
                // If old note doesn't exist, treat as CREATE
                else {
                    const note: Note = {
                        contentHash: operation.newContentHash,
                        content: operation.content,
                        createdAt: operation.timestamp,
                        updatedAt: operation.timestamp,
                        deviceId: operation.deviceId
                    };
                    notesByHash.set(operation.newContentHash, note);
                }
                break;
            }
        }
    }
    
    // Return notes sorted by creation time (newest first)
    return Array.from(notesByHash.values()).sort((a, b) => b.createdAt - a.createdAt);
}

/**
 * Update a NotesContainer with a new operation
 */
export function addOperationToContainer(
    container: NotesContainer,
    operation: Operation
): NotesContainer {
    const newOperations = [...container.operations, operation];
    const newNotes = deriveNotesFromOperations(newOperations);
    
    return {
        ...container,
        vectorClock: operation.vectorClock,
        operations: newOperations,
        notes: newNotes
    } as const;
}

/**
 * Check if a note with the given content hash exists
 */
export function noteExists(container: NotesContainer, contentHash: ContentHash): boolean {
    return container.notes.some(note => note.contentHash === contentHash);
}

/**
 * Find a note by content hash
 */
export function findNoteByHash(container: NotesContainer, contentHash: ContentHash): Note | undefined {
    return container.notes.find(note => note.contentHash === contentHash);
}

/**
 * Get all notes sorted by various criteria
 */
export function getNotesSorted(
    container: NotesContainer,
    sortBy: 'created' | 'updated' | 'content' = 'created',
    order: 'asc' | 'desc' = 'desc'
): readonly Note[] {
    const notes = [...container.notes];
    
    switch (sortBy) {
        case 'created':
            notes.sort((a, b) => order === 'desc' ? b.createdAt - a.createdAt : a.createdAt - b.createdAt);
            break;
        case 'updated':
            notes.sort((a, b) => order === 'desc' ? b.updatedAt - a.updatedAt : a.updatedAt - b.updatedAt);
            break;
        case 'content':
            notes.sort((a, b) => order === 'desc' ? b.content.localeCompare(a.content) : a.content.localeCompare(b.content));
            break;
    }
    
    return notes;
}

/**
 * Search notes by content
 */
export function searchNotes(container: NotesContainer, query: string): readonly Note[] {
    if (!query.trim()) {
        return container.notes;
    }
    
    const lowercaseQuery = query.toLowerCase();
    return container.notes.filter(note => 
        note.content.toLowerCase().includes(lowercaseQuery)
    );
}

/**
 * Get statistics about the container
 */
export interface ContainerStats {
    totalNotes: number;
    totalOperations: number;
    operationsByType: {
        CREATE: number;
        DELETE: number;
        EDIT: number;
    };
    deviceCount: number;
    oldestNote?: Timestamp;
    newestNote?: Timestamp;
    lastCompacted: Timestamp;
}

export function getContainerStats(container: NotesContainer): ContainerStats {
    const operationsByType = container.operations.reduce(
        (acc, op) => {
            acc[op.type]++;
            return acc;
        },
        { CREATE: 0, DELETE: 0, EDIT: 0 }
    );
    
    const devices = new Set(container.operations.map(op => op.deviceId));
    
    const noteTimes = container.notes.map(note => note.createdAt);
    const oldestNote = noteTimes.length > 0 ? Math.min(...noteTimes) : undefined;
    const newestNote = noteTimes.length > 0 ? Math.max(...noteTimes) : undefined;
    
    return {
        totalNotes: container.notes.length,
        totalOperations: container.operations.length,
        operationsByType,
        deviceCount: devices.size,
        ...(oldestNote !== undefined && { oldestNote }),
        ...(newestNote !== undefined && { newestNote }),
        lastCompacted: container.lastCompacted
    };
}

/**
 * Validate that a NotesContainer is well-formed
 */
export function validateContainer(container: NotesContainer): boolean {
    try {
        // Check basic structure
        if (!container.deviceId || !container.vectorClock || !Array.isArray(container.operations)) {
            return false;
        }
        
        // Validate that derived notes match operations
        const derivedNotes = deriveNotesFromOperations(container.operations);
        if (derivedNotes.length !== container.notes.length) {
            return false;
        }
        
        // Check that all notes in container match derived notes
        for (const note of container.notes) {
            const found = derivedNotes.find(n => n.contentHash === note.contentHash);
            if (!found || found.content !== note.content) {
                return false;
            }
        }
        
        return true;
    } catch {
        return false;
    }
} 