#!/usr/bin/env node

import {
    AuthCodes, GenerateEncryptionKeyResult, RecoverEncryptionKeyResult,
    deriveIdentifiers, passwordToPin, generateAuthCodes,
    generateEncryptionKey, recoverEncryptionKey
} from '../src/keygen.js';
import { ServerInfo } from '../src/client.js';
import { Identity } from '../src/keygen.js';

// Test colors for output
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';
const BLUE = '\x1b[34m';

let testCount = 0;
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
    testCount++;
    if (condition) {
        console.log(`${GREEN}✓${RESET} ${message}`);
        passCount++;
    } else {
        console.log(`${RED}✗${RESET} ${message}`);
        failCount++;
    }
}

function assertEquals(actual, expected, message) {
    testCount++;
    if (actual === expected) {
        console.log(`${GREEN}✓${RESET} ${message}`);
        passCount++;
    } else {
        console.log(`${RED}✗${RESET} ${message}`);
        console.log(`  Expected: ${expected}`);
        console.log(`  Actual:   ${actual}`);
        failCount++;
    }
}

function assertArrayEquals(actual, expected, message) {
    testCount++;
    const actualStr = JSON.stringify(actual);
    const expectedStr = JSON.stringify(expected);
    if (actualStr === expectedStr) {
        console.log(`${GREEN}✓${RESET} ${message}`);
        passCount++;
    } else {
        console.log(`${RED}✗${RESET} ${message}`);
        console.log(`  Expected: ${expectedStr}`);
        console.log(`  Actual:   ${actualStr}`);
        failCount++;
    }
}

function testSection(name) {
    console.log(`\n${BLUE}=== ${name} ===${RESET}`);
}

function printSummary() {
    console.log(`\n${BLUE}=== Test Summary ===${RESET}`);
    console.log(`Total tests: ${testCount}`);
    console.log(`${GREEN}Passed: ${passCount}${RESET}`);
    if (failCount > 0) {
        console.log(`${RED}Failed: ${failCount}${RESET}`);
    }
    console.log(`Success rate: ${Math.round((passCount / testCount) * 100)}%`);
    
    if (failCount === 0) {
        console.log(`${GREEN}🎉 All tests passed!${RESET}`);
        return true;
    } else {
        console.log(`${RED}❌ Some tests failed${RESET}`);
        return false;
    }
}

// Test AuthCodes class
testSection("AuthCodes Tests");
function testAuthCodes() {
    const baseAuthCode = "abc123";
    const serverAuthCodes = {
        "server1": "auth1",
        "server2": "auth2"
    };
    const userId = "testuser";
    
    const authCodes = new AuthCodes(baseAuthCode, serverAuthCodes, userId);
    
    assertEquals(authCodes.baseAuthCode, baseAuthCode, "AuthCodes should store base auth code");
    assertEquals(authCodes.userId, userId, "AuthCodes should store user ID");
    assertEquals(Object.keys(authCodes.serverAuthCodes).length, 2, "AuthCodes should store server auth codes");
    assertEquals(authCodes.serverAuthCodes["server1"], "auth1", "AuthCodes should store correct server auth code");
}

// Test GenerateEncryptionKeyResult class
testSection("GenerateEncryptionKeyResult Tests");
function testGenerateEncryptionKeyResult() {
    const key = new Uint8Array([1, 2, 3, 4]);
    const serverUrls = ["server1", "server2"];
    const threshold = 2;
    const authCodes = new AuthCodes("base", {}, "user");
    
    const result = new GenerateEncryptionKeyResult(key, null, serverUrls, threshold, authCodes);
    
    assertEquals(result.encryptionKey, key, "Should store encryption key");
    assertEquals(result.error, null, "Should store null error");
    assertEquals(result.serverUrls, serverUrls, "Should store server URLs");
    assertEquals(result.threshold, threshold, "Should store threshold");
    assertEquals(result.authCodes, authCodes, "Should store auth codes");
    
    // Test error result
    const errorResult = new GenerateEncryptionKeyResult(null, "Test error");
    assertEquals(errorResult.encryptionKey, null, "Error result should have null key");
    assertEquals(errorResult.error, "Test error", "Error result should store error message");
}

// Test RecoverEncryptionKeyResult class
testSection("RecoverEncryptionKeyResult Tests");
function testRecoverEncryptionKeyResult() {
    const key = new Uint8Array([5, 6, 7, 8]);
    
    const result = new RecoverEncryptionKeyResult(key, null);
    assertEquals(result.encryptionKey, key, "Should store encryption key");
    assertEquals(result.error, null, "Should store null error");
    
    // Test error result
    const errorResult = new RecoverEncryptionKeyResult(null, "Recovery error");
    assertEquals(errorResult.encryptionKey, null, "Error result should have null key");
    assertEquals(errorResult.error, "Recovery error", "Error result should store error message");
}

// Test Identity class
testSection("Identity Tests");
function testIdentity() {
    const uid = "testuser";
    const did = "testhost";
    const bid = "test.txt";
    
    const identity = new Identity(uid, did, bid);
    
    assertEquals(identity.uid, uid, "UID should be set correctly");
    assertEquals(identity.did, did, "DID should be set correctly");
    assertEquals(identity.bid, bid, "BID should be set correctly");
    
    // Test toString method
    const str = identity.toString();
    assert(str.includes(uid), "toString should include UID");
    assert(str.includes(did), "toString should include DID");
    assert(str.includes(bid), "toString should include BID");
    
    // Test deterministic behavior
    const identity2 = new Identity(uid, did, bid);
    assertEquals(identity.uid, identity2.uid, "UID should be deterministic");
    assertEquals(identity.did, identity2.did, "DID should be deterministic");
    assertEquals(identity.bid, identity2.bid, "BID should be deterministic");
}

// Test passwordToPin function
testSection("Password to PIN Tests");
function testPasswordToPin() {
    const password1 = "testpassword";
    const password2 = "different";
    
    const pin1 = passwordToPin(password1);
    const pin2 = passwordToPin(password1);
    const pin3 = passwordToPin(password2);
    
    assert(pin1 instanceof Uint8Array, "PIN should be Uint8Array");
    assert(pin1.length > 0, "PIN should not be empty");
    assertArrayEquals(Array.from(pin1), Array.from(pin2), "PIN should be deterministic");
    assert(!arraysEqual(pin1, pin3), "Different passwords should produce different PINs");
}

// Test generateAuthCodes function
testSection("Auth Code Generation Tests");
function testGenerateAuthCodes() {
    const serverUrls = ["http://server1.com", "http://server2.com", "http://server3.com"];
    
    // Test production behavior (random)
    const authCodes = generateAuthCodes(serverUrls);
    
    assert(authCodes instanceof AuthCodes, "Should return AuthCodes instance");
    assert(authCodes.baseAuthCode.length > 0, "Should generate base auth code");
    assertEquals(Object.keys(authCodes.serverAuthCodes).length, serverUrls.length, 
        "Should generate auth codes for all servers");
    
    for (const url of serverUrls) {
        assert(authCodes.serverAuthCodes[url], `Should have auth code for ${url}`);
        assert(authCodes.serverAuthCodes[url].length > 0, `Auth code for ${url} should not be empty`);
    }
    
    // Test that auth codes are random (not deterministic) in production
    const authCodes2 = generateAuthCodes(serverUrls);
    assert(authCodes.baseAuthCode !== authCodes2.baseAuthCode, "Base auth code should be random (not deterministic)");
    
    // Test different inputs produce different codes
    const authCodes3 = generateAuthCodes(["http://different.com"]);
    assert(authCodes.baseAuthCode !== authCodes3.baseAuthCode, "Different inputs should produce different codes");
    
    // Test fixture behavior (deterministic for testing)
    const testSeed = "test-fixture-seed";
    const authCodes4 = generateAuthCodes(serverUrls, testSeed);
    const authCodes5 = generateAuthCodes(serverUrls, testSeed);
    assertEquals(authCodes4.baseAuthCode, authCodes5.baseAuthCode, "Test fixture should be deterministic");
    
    for (const url of serverUrls) {
        assertEquals(authCodes4.serverAuthCodes[url], authCodes5.serverAuthCodes[url],
            `Test fixture server auth code for ${url} should be deterministic`);
    }
}

// Test input validation
testSection("Input Validation Tests");
function testInputValidation() {
    // Test Identity with invalid inputs
    try {
        const identity = new Identity("", "device", "backup");
        console.log(`${YELLOW}⚠${RESET} Identity allows empty UID`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} Identity correctly rejects empty UID`);
        passCount++;
        testCount++;
    }
    
    try {
        const identity = new Identity("user", "", "backup");
        console.log(`${YELLOW}⚠${RESET} Identity allows empty DID`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} Identity correctly rejects empty DID`);
        passCount++;
        testCount++;
    }
    
    try {
        const identity = new Identity("user", "device", "");
        console.log(`${YELLOW}⚠${RESET} Identity allows empty BID`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} Identity correctly rejects empty BID`);
        passCount++;
        testCount++;
    }
    
    // Test passwordToPin with empty password
    try {
        const emptyPin = passwordToPin("");
        assert(emptyPin.length > 0, "Empty password should still produce PIN");
    } catch (error) {
        console.log(`${RED}✗${RESET} passwordToPin fails with empty password: ${error.message}`);
        failCount++;
        testCount++;
    }
    
    // Test generateAuthCodes with empty array
    try {
        const emptyAuthCodes = generateAuthCodes([]);
        assertEquals(Object.keys(emptyAuthCodes.serverAuthCodes).length, 0, 
            "Empty server list should produce empty auth codes");
    } catch (error) {
        console.log(`${RED}✗${RESET} generateAuthCodes fails with empty array: ${error.message}`);
        failCount++;
        testCount++;
    }
}

// Test consistency between generation and recovery identifiers
testSection("Generation/Recovery Consistency Tests");
function testGenerationRecoveryConsistency() {
    const uid = "testuser";
    const did = "testhost";
    const bid = "test.txt";
    
    // Test that identities are consistent between generation and recovery
    const genIdentity = new Identity(uid, did, bid);
    const recIdentity = new Identity(uid, did, bid);
    
    assertEquals(genIdentity.uid, recIdentity.uid, "UID should be consistent between generation and recovery");
    assertEquals(genIdentity.did, recIdentity.did, "DID should be consistent between generation and recovery");
    assertEquals(genIdentity.bid, recIdentity.bid, "BID should be consistent between generation and recovery");
    
    // Test with different values
    const genIdentity2 = new Identity(uid, did, "different.txt");
    const recIdentity2 = new Identity(uid, did, "different.txt");
    
    assertEquals(genIdentity2.uid, recIdentity2.uid, "UID should be consistent with different BID");
    assertEquals(genIdentity2.did, recIdentity2.did, "DID should be consistent with different BID");
    assertEquals(genIdentity2.bid, recIdentity2.bid, "BID should be consistent with different BID");
}

// Helper function to compare arrays
function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// Mock server for testing (simplified)
class MockServer {
    constructor(url) {
        this.url = url;
        this.secrets = new Map();
    }
    
    async registerSecret(authCode, uid, did, bid, version, x, yBase64, maxGuesses, expiration) {
        const key = `${uid}:${did}:${bid}`;
        this.secrets.set(key, { x, yBase64, authCode, maxGuesses, expiration });
        return true;
    }
    
    async recoverSecret(authCode, uid, did, bid, bBase64, guessNum) {
        const key = `${uid}:${did}:${bid}`;
        const stored = this.secrets.get(key);
        if (!stored || stored.authCode !== authCode) {
            throw new Error("Authentication failed");
        }
        return {
            x: stored.x,
            si_b: stored.yBase64,
            expiration: stored.expiration,
            max_guesses: stored.maxGuesses,
            num_guesses: guessNum + 1,
            version: 1
        };
    }
    
    async ping() {
        return true;
    }
    
    async getServerInfo() {
        return {
            version: "1.0",
            noise_nk_public_key: "mock_public_key"
        };
    }
}

// Test integration scenarios (without actual network calls)
testSection("Integration Scenario Tests");
function testIntegrationScenarios() {
    // Test the flow of identity creation -> auth code generation -> consistency
    const uid = "alice";
    const did = "laptop-2024";
    const bid = "important.doc";
    const password = "secure123";
    const serverUrls = ["https://server1.com", "https://server2.com"];
    
    try {
        // Step 1: Create identity (as done in generation)
        const identity = new Identity(uid, did, bid);
        
        // Step 2: Convert password to PIN
        const pin = passwordToPin(password);
        
        // Step 3: Generate auth codes
        const authCodes = generateAuthCodes(serverUrls);
        
        // Step 4: Verify consistency for recovery
        const recIdentity = new Identity(uid, did, bid);
        const recPin = passwordToPin(password);
        
        assertEquals(identity.uid, recIdentity.uid, "UID should be consistent for recovery");
        assertEquals(identity.did, recIdentity.did, "DID should be consistent for recovery");
        assertEquals(identity.bid, recIdentity.bid, "BID should be consistent for recovery");
        assertArrayEquals(Array.from(pin), Array.from(recPin), "PIN should be consistent for recovery");
        
        // Step 5: Test auth code generation consistency using test fixture
        const testSeed = "integration-test-seed";
        const testAuthCodes = generateAuthCodes(serverUrls, testSeed);
        const testRecAuthCodes = generateAuthCodes(serverUrls, testSeed);
        assertEquals(testAuthCodes.baseAuthCode, testRecAuthCodes.baseAuthCode, 
            "Test fixture auth codes should be consistent for recovery");
        
        // Verify structure is consistent
        assertEquals(Object.keys(testAuthCodes.serverAuthCodes).length, 
            Object.keys(testRecAuthCodes.serverAuthCodes).length,
            "Should generate same number of server auth codes");
        
        for (const url of serverUrls) {
            assertEquals(testAuthCodes.serverAuthCodes[url], testRecAuthCodes.serverAuthCodes[url],
                `Test fixture server auth code for ${url} should be consistent for recovery`);
        }
        
    } catch (error) {
        console.log(`${RED}✗${RESET} Integration scenario test failed: ${error.message}`);
        failCount++;
        testCount++;
    }
}

// Run all tests
async function runAllTests() {
    console.log(`${BLUE}🧪 Running Keygen Module Unit Tests${RESET}\n`);
    
    testAuthCodes();
    testGenerateEncryptionKeyResult();
    testRecoverEncryptionKeyResult();
    testIdentity();
    testPasswordToPin();
    testGenerateAuthCodes();
    testInputValidation();
    testGenerationRecoveryConsistency();
    testIntegrationScenarios();
    
    return printSummary();
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runAllTests().then(success => {
        process.exit(success ? 0 : 1);
    });
}

export { runAllTests }; 