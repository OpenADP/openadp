import type { VectorClock, DeviceId } from '../types/index.js';

/**
 * Vector Clock Implementation for Distributed Operations
 * 
 * Provides causal ordering for operations in a distributed system.
 * Each device maintains a logical clock that increments with each operation.
 */

/**
 * Creates a new vector clock with the given device initialized to 0
 */
export function createVectorClock(deviceId: DeviceId): VectorClock {
  return { [deviceId]: 0 } as const;
}

/**
 * Increments the vector clock for the specified device
 */
export function incrementVectorClock(
  vectorClock: VectorClock, 
  deviceId: DeviceId
): VectorClock {
  return {
    ...vectorClock,
    [deviceId]: (vectorClock[deviceId] ?? 0) + 1
  } as const;
}

/**
 * Merges two vector clocks, taking the maximum value for each device
 */
export function mergeVectorClocks(
  clock1: VectorClock, 
  clock2: VectorClock
): VectorClock {
  const allDevices = new Set([
    ...Object.keys(clock1),
    ...Object.keys(clock2)
  ]);

  const merged: Record<DeviceId, number> = {};
  
  for (const deviceId of allDevices) {
    merged[deviceId] = Math.max(
      clock1[deviceId] ?? 0,
      clock2[deviceId] ?? 0
    );
  }

  return merged as VectorClock;
}

/**
 * Comparison result for vector clocks
 */
export type VectorClockComparison = 'before' | 'after' | 'concurrent' | 'equal';

/**
 * Compares two vector clocks to determine their causal relationship
 */
export function compareVectorClocks(
  clock1: VectorClock, 
  clock2: VectorClock
): VectorClockComparison {
  const allDevices = new Set([
    ...Object.keys(clock1),
    ...Object.keys(clock2)
  ]);

  let clock1Greater = false;
  let clock2Greater = false;

  for (const deviceId of allDevices) {
    const value1 = clock1[deviceId] ?? 0;
    const value2 = clock2[deviceId] ?? 0;

    if (value1 > value2) {
      clock1Greater = true;
    } else if (value2 > value1) {
      clock2Greater = true;
    }
  }

  if (clock1Greater && clock2Greater) {
    return 'concurrent';
  } else if (clock1Greater) {
    return 'after';
  } else if (clock2Greater) {
    return 'before';
  } else {
    return 'equal';
  }
}

/**
 * Checks if two vector clocks are concurrent (neither causally precedes the other)
 */
export function areConcurrent(clock1: VectorClock, clock2: VectorClock): boolean {
  return compareVectorClocks(clock1, clock2) === 'concurrent';
}

/**
 * Checks if clock1 causally precedes clock2
 */
export function happensBefore(clock1: VectorClock, clock2: VectorClock): boolean {
  return compareVectorClocks(clock1, clock2) === 'before';
}

/**
 * Gets the logical timestamp for a specific device from the vector clock
 */
export function getDeviceTime(vectorClock: VectorClock, deviceId: DeviceId): number {
  return vectorClock[deviceId] ?? 0;
}

/**
 * Creates a human-readable string representation of a vector clock
 */
export function vectorClockToString(vectorClock: VectorClock): string {
  const entries = Object.entries(vectorClock)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([deviceId, time]) => `${deviceId.slice(0, 8)}:${time}`);
  
  return `{${entries.join(', ')}}`;
}

/**
 * Validates that a vector clock has the correct structure
 */
export function isValidVectorClock(obj: unknown): obj is VectorClock {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }

  const clock = obj as Record<string, unknown>;
  
  return Object.values(clock).every(
    value => typeof value === 'number' && Number.isInteger(value) && value >= 0
  );
} 