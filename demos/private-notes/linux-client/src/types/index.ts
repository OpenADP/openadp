// Core Types for Private Notes App

/** Device identifier - UUID v4 format */
export type DeviceId = string;

/** Content hash - SHA-256 hex string */
export type ContentHash = string;

/** Operation identifier - UUID v4 format */
export type OperationId = string;

/** Timestamp in milliseconds since Unix epoch */
export type Timestamp = number;

/** Vector clock mapping device IDs to logical timestamps */
export interface VectorClock {
  readonly [deviceId: DeviceId]: number;
}

/** Operation types for note management */
export type OperationType = 'CREATE' | 'DELETE' | 'EDIT';

/** Base operation interface */
export interface BaseOperation {
  readonly id: OperationId;
  readonly type: OperationType;
  readonly deviceId: DeviceId;
  readonly timestamp: Timestamp;
  readonly vectorClock: VectorClock;
}

/** CREATE operation - creates a new note */
export interface CreateOperation extends BaseOperation {
  readonly type: 'CREATE';
  readonly contentHash: ContentHash;
  readonly content: string;
}

/** DELETE operation - deletes an existing note */
export interface DeleteOperation extends BaseOperation {
  readonly type: 'DELETE';
  readonly contentHash: ContentHash;
}

/** EDIT operation - modifies an existing note */
export interface EditOperation extends BaseOperation {
  readonly type: 'EDIT';
  readonly oldContentHash: ContentHash;
  readonly newContentHash: ContentHash;
  readonly content: string;
}

/** Union type for all operations */
export type Operation = CreateOperation | DeleteOperation | EditOperation;

/** Note representation derived from operations */
export interface Note {
  readonly contentHash: ContentHash;
  readonly content: string;
  readonly createdAt: Timestamp;
  readonly updatedAt: Timestamp;
  readonly deviceId: DeviceId;
}

/** Container for all notes data with operation log */
export interface NotesContainer {
  readonly version: number;
  readonly deviceId: DeviceId;
  readonly vectorClock: VectorClock;
  readonly operations: readonly Operation[];
  readonly notes: readonly Note[];
  readonly lastCompacted: Timestamp;
}

/** Encrypted blob metadata for OpenADP format */
export interface BlobMetadata {
  readonly version: number;
  readonly deviceId: DeviceId;
  readonly timestamp: Timestamp;
  readonly algorithm: 'ChaCha20-Poly1305';
}

/** Encrypted blob structure matching openadp-encrypt.go format */
export interface EncryptedBlob {
  readonly metadata: BlobMetadata;
  readonly nonce: Uint8Array;
  readonly encryptedData: Uint8Array;
}

/** Sync status for cloud synchronization */
export type SyncStatus = 'idle' | 'syncing' | 'error' | 'offline';

/** Sync result after attempting synchronization */
export interface SyncResult {
  readonly success: boolean;
  readonly timestamp: Timestamp;
  readonly operationsAdded: number;
  readonly operationsCompacted: number;
  readonly error?: string;
}

/** Configuration for the application */
export interface AppConfig {
  readonly openadpServers: readonly string[];
  readonly cloudflareR2: {
    readonly endpoint: string;
    readonly bucket: string;
    readonly region: string;
  };
  readonly crypto: {
    readonly algorithm: 'ChaCha20-Poly1305';
    readonly keyDerivation: 'PBKDF2';
    readonly iterations: number;
  };
}

/** User interface state */
export interface UIState {
  readonly isLoggedIn: boolean;
  readonly currentNoteHash?: ContentHash;
  readonly searchQuery: string;
  readonly syncStatus: SyncStatus;
  readonly lastSyncTime?: Timestamp;
}

/** Error types for better error handling */
export type AppError = 
  | { type: 'CRYPTO_ERROR'; message: string; cause?: Error }
  | { type: 'STORAGE_ERROR'; message: string; cause?: Error }
  | { type: 'NETWORK_ERROR'; message: string; cause?: Error }
  | { type: 'VALIDATION_ERROR'; message: string; field?: string }
  | { type: 'OPENADP_ERROR'; message: string; serverErrors?: string[] };

/** Type guards for runtime type checking */
export const isOperation = (obj: unknown): obj is Operation => {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'id' in obj &&
    'type' in obj &&
    'deviceId' in obj &&
    'timestamp' in obj &&
    'vectorClock' in obj &&
    ['CREATE', 'DELETE', 'EDIT'].includes((obj as any).type)
  );
};

export const isCreateOperation = (op: Operation): op is CreateOperation => {
  return op.type === 'CREATE' && 'content' in op && 'contentHash' in op;
};

export const isDeleteOperation = (op: Operation): op is DeleteOperation => {
  return op.type === 'DELETE' && 'contentHash' in op;
};

export const isEditOperation = (op: Operation): op is EditOperation => {
  return op.type === 'EDIT' && 'oldContentHash' in op && 'newContentHash' in op && 'content' in op;
};

/** Utility types for working with operations */
export type OperationsByType<T extends OperationType> = Extract<Operation, { type: T }>;

/** Immutable update helpers */
export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends (infer U)[]
    ? readonly DeepReadonly<U>[]
    : T[P] extends object
    ? DeepReadonly<T[P]>
    : T[P];
};

/** Make all properties of NotesContainer deeply readonly */
export type ImmutableNotesContainer = DeepReadonly<NotesContainer>; 