import { 
    createVectorClock,
    incrementVectorClock,
    mergeVectorClocks,
    compareVectorClocks,
    areConcurrent,
    happensBefore,
    vectorClockToString,
    isValidVectorClock
} from './vector-clock.js';

/**
 * Test Results Interface
 */
interface TestResult {
    success: boolean;
    message: string;
    details?: string;
    error?: Error;
}

/**
 * Display test results in the UI
 */
function displayResults(elementId: string, results: TestResult[]): void {
    const element = document.getElementById(elementId);
    if (!element) return;

    const allPassed = results.every(r => r.success);
    element.className = `test-results ${allPassed ? 'success' : 'error'}`;
    
    const output = results.map(result => {
        const status = result.success ? '✅' : '❌';
        let message = `${status} ${result.message}`;
        
        if (result.details) {
            message += `\n   ${result.details}`;
        }
        
        if (result.error) {
            message += `\n   Error: ${result.error.message}`;
        }
        
        return message;
    }).join('\n\n');
    
    element.textContent = output;
}

/**
 * Test vector clock functionality
 */
async function testVectorClocks(): Promise<TestResult[]> {
    const results: TestResult[] = [];
    
    try {
        // Test 1: Create vector clocks
        const device1 = 'device-1';
        const device2 = 'device-2';
        const device3 = 'device-3';
        
        const clock1 = createVectorClock(device1);
        const clock2 = createVectorClock(device2);
        
        results.push({
            success: clock1[device1] === 0,
            message: 'Vector Clock Creation',
            details: `Device 1 clock: ${vectorClockToString(clock1)}`
        });

        // Test 2: Increment vector clocks
        const clock1_1 = incrementVectorClock(clock1, device1);
        const clock1_2 = incrementVectorClock(clock1_1, device1);
        
        results.push({
            success: clock1_2[device1] === 2,
            message: 'Vector Clock Increment',
            details: `After 2 increments: ${vectorClockToString(clock1_2)}`
        });

        // Test 3: Compare vector clocks - equal
        const comparison1 = compareVectorClocks(clock1, clock2);
        
        results.push({
            success: comparison1 === 'concurrent',
            message: 'Vector Clock Comparison - Concurrent',
            details: `${vectorClockToString(clock1)} vs ${vectorClockToString(clock2)} = ${comparison1}`
        });

        // Test 4: Compare vector clocks - before/after
        const comparison2 = compareVectorClocks(clock1, clock1_2);
        
        results.push({
            success: comparison2 === 'before',
            message: 'Vector Clock Comparison - Before',
            details: `${vectorClockToString(clock1)} vs ${vectorClockToString(clock1_2)} = ${comparison2}`
        });

        // Test 5: Merge vector clocks
        const clock2_1 = incrementVectorClock(clock2, device2);
        const merged = mergeVectorClocks(clock1_2, clock2_1);
        
        const expectedMerged = merged[device1] === 2 && merged[device2] === 1;
        
        results.push({
            success: expectedMerged,
            message: 'Vector Clock Merge',
            details: `Merged: ${vectorClockToString(merged)}`
        });

        // Test 6: Concurrent operations
        const clock3 = createVectorClock(device3);
        const clock3_1 = incrementVectorClock(clock3, device3);
        
        const areConcurrentResult = areConcurrent(clock1_2, clock3_1);
        
        results.push({
            success: areConcurrentResult,
            message: 'Concurrent Detection',
            details: `${vectorClockToString(clock1_2)} and ${vectorClockToString(clock3_1)} are concurrent: ${areConcurrentResult}`
        });

        // Test 7: Happens-before relationship
        const clock1_3 = incrementVectorClock(merged, device1);
        const happensBeforeResult = happensBefore(merged, clock1_3);
        
        results.push({
            success: happensBeforeResult,
            message: 'Happens-Before Relationship',
            details: `${vectorClockToString(merged)} happens before ${vectorClockToString(clock1_3)}: ${happensBeforeResult}`
        });

        // Test 8: Complex concurrent scenario
        // Device 1: [1,0,0] -> [2,0,0]
        // Device 2: [0,1,0] -> [0,2,0]
        // These should be concurrent
        
        const complexClock1 = incrementVectorClock(incrementVectorClock(createVectorClock(device1), device1), device1);
        const complexClock2 = incrementVectorClock(incrementVectorClock(createVectorClock(device2), device2), device2);
        
        const complexConcurrent = areConcurrent(complexClock1, complexClock2);
        
        results.push({
            success: complexConcurrent,
            message: 'Complex Concurrent Scenario',
            details: `${vectorClockToString(complexClock1)} vs ${vectorClockToString(complexClock2)} = concurrent: ${complexConcurrent}`
        });

        // Test 9: Causal relationship
        // Start with [1,1,0], then increment device1 to get [2,1,0]
        // [1,1,0] should happen before [2,1,0]
        
        const causalBase = mergeVectorClocks(
            incrementVectorClock(createVectorClock(device1), device1),
            incrementVectorClock(createVectorClock(device2), device2)
        );
        const causalNext = incrementVectorClock(causalBase, device1);
        
        const causalRelation = happensBefore(causalBase, causalNext);
        
        results.push({
            success: causalRelation,
            message: 'Causal Relationship',
            details: `${vectorClockToString(causalBase)} → ${vectorClockToString(causalNext)} = causal: ${causalRelation}`
        });

        // Test 10: Vector clock validation
        const validClock = { 'device-a': 5, 'device-b': 3 };
        const invalidClock1 = { 'device-a': -1, 'device-b': 3 };
        const invalidClock2 = { 'device-a': 5.5, 'device-b': 3 };
        
        results.push({
            success: isValidVectorClock(validClock) && 
                     !isValidVectorClock(invalidClock1) && 
                     !isValidVectorClock(invalidClock2),
            message: 'Vector Clock Validation',
            details: `Valid: ${isValidVectorClock(validClock)}, Invalid (negative): ${!isValidVectorClock(invalidClock1)}, Invalid (float): ${!isValidVectorClock(invalidClock2)}`
        });

        // Test 11: String representation
        const stringRepr = vectorClockToString(merged);
        const hasDevices = stringRepr.includes(device1.slice(0, 8)) && stringRepr.includes(device2.slice(0, 8));
        
        results.push({
            success: hasDevices,
            message: 'String Representation',
            details: `String: ${stringRepr}`
        });

        // Test 12: Empty vector clock edge case
        const emptyClock = {};
        const emptyComparison = compareVectorClocks(emptyClock, emptyClock);
        
        results.push({
            success: emptyComparison === 'equal',
            message: 'Empty Vector Clock',
            details: `Empty clocks comparison: ${emptyComparison}`
        });

    } catch (error) {
        results.push({
            success: false,
            message: 'Vector Clock Test Failed',
            error: error as Error
        });
    }
    
    return results;
}

/**
 * Test distributed scenario with multiple devices
 */
async function testDistributedScenario(): Promise<TestResult[]> {
    const results: TestResult[] = [];
    
    try {
        // Simulate a distributed system with 3 devices
        const alice = 'alice-device';
        const bob = 'bob-device';
        const charlie = 'charlie-device';
        
        // Initial state - all devices start at 0
        let aliceClock = createVectorClock(alice);
        let bobClock = createVectorClock(bob);
        let charlieClock = createVectorClock(charlie);
        
        // Alice creates a note (increment her clock)
        aliceClock = incrementVectorClock(aliceClock, alice);
        
        // Bob creates a note concurrently (doesn't know about Alice's note yet)
        bobClock = incrementVectorClock(bobClock, bob);
        
        // Alice and Bob's operations are concurrent
        const aliceBobConcurrent = areConcurrent(aliceClock, bobClock);
        
        results.push({
            success: aliceBobConcurrent,
            message: 'Distributed Scenario - Concurrent Operations',
            details: `Alice: ${vectorClockToString(aliceClock)}, Bob: ${vectorClockToString(bobClock)} = concurrent: ${aliceBobConcurrent}`
        });
        
        // Alice syncs with Bob - she merges Bob's clock with hers
        aliceClock = mergeVectorClocks(aliceClock, bobClock);
        
        // Alice creates another note (now she knows about Bob's operation)
        aliceClock = incrementVectorClock(aliceClock, alice);
        
        // Charlie syncs with Alice and creates a note
        charlieClock = mergeVectorClocks(charlieClock, aliceClock);
        charlieClock = incrementVectorClock(charlieClock, charlie);
        
        // Charlie's note should happen after both Alice's and Bob's original notes
        const charlieAfterAlice = happensBefore(
            { [alice]: 1, [bob]: 0 }, 
            charlieClock
        );
        const charlieAfterBob = happensBefore(
            { [alice]: 0, [bob]: 1 }, 
            charlieClock
        );
        
        results.push({
            success: charlieAfterAlice && charlieAfterBob,
            message: 'Distributed Scenario - Causal Ordering',
            details: `Charlie's operation causally follows both Alice's and Bob's original operations`
        });
        
        // Final state should show the complete history
        const finalMerged = mergeVectorClocks(mergeVectorClocks(aliceClock, bobClock), charlieClock);
        const expectedFinal = finalMerged[alice] === 2 && finalMerged[bob] === 1 && finalMerged[charlie] === 1;
        
        results.push({
            success: expectedFinal,
            message: 'Distributed Scenario - Final State',
            details: `Final merged state: ${vectorClockToString(finalMerged)}`
        });
        
    } catch (error) {
        results.push({
            success: false,
            message: 'Distributed Scenario Test Failed',
            error: error as Error
        });
    }
    
    return results;
}

/**
 * Initialize vector clock tests
 */
function initVectorClockTests(): void {
    const testBtn = document.getElementById('test-vector-clock-btn');

    if (testBtn) {
        testBtn.addEventListener('click', async () => {
            testBtn.textContent = 'Testing...';
            (testBtn as HTMLButtonElement).disabled = true;
            
            try {
                const basicResults = await testVectorClocks();
                const distributedResults = await testDistributedScenario();
                const allResults = [...basicResults, ...distributedResults];
                
                displayResults('vector-clock-results', allResults);
            } finally {
                testBtn.textContent = 'Test Vector Clocks';
                (testBtn as HTMLButtonElement).disabled = false;
            }
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initVectorClockTests);
} else {
    initVectorClockTests();
} 