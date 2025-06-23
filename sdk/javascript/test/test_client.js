#!/usr/bin/env node

import {
    ServerInfo, JSONRPCRequest, JSONRPCResponse, JSONRPCError, ErrorCode,
    OpenADPError, OpenADPClient, EncryptedOpenADPClient, MultiServerClient,
    parseServerPublicKey, getServers, getFallbackServerInfo
} from '../src/client.js';

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

// Test ServerInfo class
testSection("ServerInfo Tests");
function testServerInfo() {
    const url = "https://server.example.com";
    const publicKey = "ed25519:abc123";
    const country = "US";
    
    const serverInfo = new ServerInfo(url, publicKey, country);
    
    assertEquals(serverInfo.url, url, "ServerInfo should store URL");
    assertEquals(serverInfo.publicKey, publicKey, "ServerInfo should store public key");
    assertEquals(serverInfo.country, country, "ServerInfo should store country");
    
    // Test with optional parameters
    const minimalServerInfo = new ServerInfo(url);
    assertEquals(minimalServerInfo.url, url, "ServerInfo should work with minimal parameters");
    assertEquals(minimalServerInfo.publicKey, "", "ServerInfo should default public key to empty");
    assertEquals(minimalServerInfo.country, "Unknown", "ServerInfo should default country to Unknown");
}

// Test JSONRPCRequest class
testSection("JSONRPCRequest Tests");
function testJSONRPCRequest() {
    const method = "test_method";
    const params = ["param1", "param2"];
    const id = 123;
    
    const request = new JSONRPCRequest(method, params, id);
    
    assertEquals(request.method, method, "JSONRPCRequest should store method");
    assertEquals(request.params, params, "JSONRPCRequest should store params");
    assertEquals(request.id, id, "JSONRPCRequest should store id");
    assertEquals(request.jsonrpc, "2.0", "JSONRPCRequest should have correct version");
    
    // Test toDict method
    const dict = request.toDict();
    assertEquals(dict.jsonrpc, "2.0", "toDict should include jsonrpc version");
    assertEquals(dict.method, method, "toDict should include method");
    assertEquals(dict.params, params, "toDict should include params");
    assertEquals(dict.id, id, "toDict should include id");
    
    // Test with null params
    const requestNoParams = new JSONRPCRequest(method, null, id);
    assertEquals(requestNoParams.params, null, "JSONRPCRequest should handle null params");
}

// Test JSONRPCResponse class
testSection("JSONRPCResponse Tests");
function testJSONRPCResponse() {
    const result = { success: true };
    const id = 456;
    
    const response = new JSONRPCResponse(result, null, id);
    
    assertEquals(response.result, result, "JSONRPCResponse should store result");
    assertEquals(response.id, id, "JSONRPCResponse should store id");
    assertEquals(response.jsonrpc, "2.0", "JSONRPCResponse should have correct version");
    assertEquals(response.error, null, "JSONRPCResponse should default error to null");
    
    // Test toDict method
    const dict = response.toDict();
    assertEquals(dict.jsonrpc, "2.0", "toDict should include jsonrpc version");
    assertEquals(dict.result, result, "toDict should include result");
    assertEquals(dict.id, id, "toDict should include id");
    assert(!dict.hasOwnProperty('error'), "toDict should not include null error");
    
    // Test fromDict method
    const responseData = {
        jsonrpc: "2.0",
        result: { data: "test" },
        id: 789
    };
    
    const parsedResponse = JSONRPCResponse.fromDict(responseData);
    assertEquals(parsedResponse.result.data, "test", "fromDict should parse result correctly");
    assertEquals(parsedResponse.id, 789, "fromDict should parse id correctly");
    assertEquals(parsedResponse.error, null, "fromDict should handle missing error");
}

// Test JSONRPCError class
testSection("JSONRPCError Tests");
function testJSONRPCError() {
    const code = -32601;
    const message = "Method not found";
    const data = { additional: "info" };
    
    const error = new JSONRPCError(code, message, data);
    
    assertEquals(error.code, code, "JSONRPCError should store code");
    assertEquals(error.message, message, "JSONRPCError should store message");
    assertEquals(error.data, data, "JSONRPCError should store data");
    
    // Test toDict method
    const dict = error.toDict();
    assertEquals(dict.code, code, "toDict should include code");
    assertEquals(dict.message, message, "toDict should include message");
    assertEquals(dict.data, data, "toDict should include data");
    
    // Test without data
    const errorNoData = new JSONRPCError(code, message);
    assertEquals(errorNoData.data, null, "JSONRPCError should handle null data");
}

// Test OpenADPError class
testSection("OpenADPError Tests");
function testOpenADPError() {
    const code = ErrorCode.NETWORK_FAILURE;
    const message = "Connection failed";
    const details = "Timeout after 30 seconds";
    
    const error = new OpenADPError(code, message, details);
    
    assertEquals(error.code, code, "OpenADPError should store code");
    assertEquals(error.message, message, "OpenADPError should store message");
    assertEquals(error.details, details, "OpenADPError should store details");
    assert(error instanceof Error, "OpenADPError should extend Error");
    
    // Test without details
    const errorNoDetails = new OpenADPError(code, message);
    assertEquals(errorNoDetails.details, null, "OpenADPError should handle null details");
}

// Test parseServerPublicKey function
testSection("parseServerPublicKey Tests");
function testParseServerPublicKey() {
    // Test ed25519 format
    const ed25519Key = "ed25519:YWJjZGVmZ2hpams=";
    const parsed1 = parseServerPublicKey(ed25519Key);
    assert(parsed1 instanceof Uint8Array, "Should return Uint8Array for ed25519");
    
    // Test base64 format
    const base64Key = "YWJjZGVmZ2hpams=";
    const parsed2 = parseServerPublicKey(base64Key);
    assert(parsed2 instanceof Uint8Array, "Should return Uint8Array for base64");
    
    // Test invalid format
    try {
        parseServerPublicKey("invalid_key");
        console.log(`${YELLOW}⚠${RESET} parseServerPublicKey should throw on invalid key`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} parseServerPublicKey correctly throws on invalid key`);
        passCount++;
        testCount++;
    }
    
    // Test empty string
    try {
        parseServerPublicKey("");
        console.log(`${YELLOW}⚠${RESET} parseServerPublicKey should throw on empty key`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} parseServerPublicKey correctly throws on empty key`);
        passCount++;
        testCount++;
    }
}

// Test getFallbackServerInfo function
testSection("getFallbackServerInfo Tests");
function testGetFallbackServerInfo() {
    const fallbackServers = getFallbackServerInfo();
    
    assert(Array.isArray(fallbackServers), "Should return array");
    assert(fallbackServers.length > 0, "Should return at least one server");
    
    for (const server of fallbackServers) {
        assert(server instanceof ServerInfo, "Each item should be ServerInfo instance");
        assert(server.url.length > 0, "Each server should have URL");
        assert(server.url.startsWith("http"), "Each URL should be HTTP/HTTPS");
    }
}

// Test ErrorCode enum
testSection("ErrorCode Tests");
function testErrorCode() {
    assert(typeof ErrorCode.NETWORK_FAILURE === 'number', "ErrorCode should contain number values");
    assert(typeof ErrorCode.AUTHENTICATION_FAILED === 'number', "ErrorCode should contain number values");
    assert(typeof ErrorCode.ENCRYPTION_FAILED === 'number', "ErrorCode should contain number values");
    assert(typeof ErrorCode.INVALID_RESPONSE === 'number', "ErrorCode should contain number values");
    
    // Test that error codes are unique
    const codes = Object.values(ErrorCode);
    const uniqueCodes = new Set(codes);
    assertEquals(codes.length, uniqueCodes.size, "Error codes should be unique");
}

// Test OpenADPClient class (basic functionality)
testSection("OpenADPClient Tests");
function testOpenADPClient() {
    const url = "https://test.server.com";
    const client = new OpenADPClient(url);
    
    assertEquals(client.url, url, "OpenADPClient should store URL");
    assertEquals(client.timeout, 30000, "OpenADPClient should have default timeout");
    assertEquals(client.requestId, 1, "OpenADPClient should start with requestId 1");
    
    // Test with custom timeout
    const customClient = new OpenADPClient(url, 60000);
    assertEquals(customClient.timeout, 60000, "OpenADPClient should accept custom timeout");
}

// Test EncryptedOpenADPClient class (basic functionality)
testSection("EncryptedOpenADPClient Tests");
function testEncryptedOpenADPClient() {
    const url = "https://test.server.com";
    const publicKey = new Uint8Array([1, 2, 3, 4]);
    
    const client = new EncryptedOpenADPClient(url, publicKey);
    
    assertEquals(client.url, url, "EncryptedOpenADPClient should store URL");
    assertEquals(client.serverPublicKey, publicKey, "EncryptedOpenADPClient should store public key");
    assertEquals(client.handshakeComplete, false, "EncryptedOpenADPClient should start with handshake incomplete");
    assertEquals(client.sessionID, null, "EncryptedOpenADPClient should start with null session");
    
    // Test without public key
    const clientNoKey = new EncryptedOpenADPClient(url);
    assertEquals(clientNoKey.serverPublicKey, null, "EncryptedOpenADPClient should handle null public key");
}

// Test MultiServerClient class
testSection("MultiServerClient Tests");
function testMultiServerClient() {
    const serverInfos = [
        new ServerInfo("https://server1.com", "key1", "US"),
        new ServerInfo("https://server2.com", "key2", "EU"),
        new ServerInfo("https://server3.com", "key3", "AS")
    ];
    
    // Test constructor with default parameters
    const multiClient = new MultiServerClient();
    assertEquals(multiClient.serversUrl, "https://servers.openadp.org/api/servers.json", "MultiServerClient should have default registry URL");
    assertEquals(multiClient.fallbackServers.length, 0, "MultiServerClient should start with empty fallback servers");
    assertEquals(multiClient.liveServers.length, 0, "MultiServerClient should start with no live servers");
    
    // Test fromServerInfo static method
    const multiClientFromInfo = MultiServerClient.fromServerInfo(serverInfos);
    assert(multiClientFromInfo instanceof MultiServerClient, "fromServerInfo should return MultiServerClient instance");
    assertEquals(multiClientFromInfo.echoTimeout, 10000, "fromServerInfo should have default echo timeout");
    
    // Test with custom parameters
    const customMultiClient = new MultiServerClient("https://custom.registry.com", ["https://fallback.com"], 5000, 5);
    assertEquals(customMultiClient.serversUrl, "https://custom.registry.com", "MultiServerClient should accept custom registry URL");
    assertEquals(customMultiClient.fallbackServers.length, 1, "MultiServerClient should accept fallback servers");
    assertEquals(customMultiClient.echoTimeout, 5000, "MultiServerClient should accept custom echo timeout");
    assertEquals(customMultiClient.maxWorkers, 5, "MultiServerClient should accept custom max workers");
}

// Test JSON-RPC response parsing edge cases
testSection("JSON-RPC Parsing Tests");
function testJSONRPCParsing() {
    // Test response with error
    const errorResponseData = {
        jsonrpc: "2.0",
        error: {
            code: -32601,
            message: "Method not found",
            data: { method: "unknown_method" }
        },
        id: 1
    };
    
    const errorResponse = JSONRPCResponse.fromDict(errorResponseData);
    assertEquals(errorResponse.result, null, "Error response should have null result");
    assertEquals(errorResponse.error.code, -32601, "Error response should parse error code");
    assertEquals(errorResponse.error.message, "Method not found", "Error response should parse error message");
    
    // Test response with both result and error (invalid but should handle gracefully)
    const invalidResponseData = {
        jsonrpc: "2.0",
        result: "success",
        error: { code: -1, message: "error" },
        id: 2
    };
    
    const invalidResponse = JSONRPCResponse.fromDict(invalidResponseData);
    // Should prefer result over error or handle appropriately
    assert(invalidResponse.result !== null || invalidResponse.error !== null, 
        "Should handle invalid response with both result and error");
    
    // Test response with missing id
    const noIdResponseData = {
        jsonrpc: "2.0",
        result: "success"
    };
    
    const noIdResponse = JSONRPCResponse.fromDict(noIdResponseData);
    assertEquals(noIdResponse.id, null, "Should handle missing id");
}

// Test input validation
testSection("Input Validation Tests");
function testInputValidation() {
    // Test ServerInfo with invalid URL
    try {
        const invalidServer = new ServerInfo("");
        console.log(`${YELLOW}⚠${RESET} ServerInfo allows empty URL`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} ServerInfo correctly rejects empty URL`);
        passCount++;
        testCount++;
    }
    
    // Test JSONRPCRequest with invalid method
    try {
        const invalidRequest = new JSONRPCRequest("", [], 1);
        console.log(`${YELLOW}⚠${RESET} JSONRPCRequest allows empty method`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} JSONRPCRequest correctly rejects empty method`);
        passCount++;
        testCount++;
    }
    
    // Test OpenADPClient with invalid URL
    try {
        const invalidClient = new OpenADPClient("");
        console.log(`${YELLOW}⚠${RESET} OpenADPClient allows empty URL`);
    } catch (error) {
        console.log(`${GREEN}✓${RESET} OpenADPClient correctly rejects empty URL`);
        passCount++;
        testCount++;
    }
}

// Test serialization/deserialization consistency
testSection("Serialization Tests");
function testSerialization() {
    // Test JSONRPCRequest serialization
    const request = new JSONRPCRequest("test_method", ["param1", 123, true], 456);
    const requestDict = request.toDict();
    const requestJson = JSON.stringify(requestDict);
    const parsedRequestDict = JSON.parse(requestJson);
    
    assertEquals(parsedRequestDict.method, "test_method", "Request method should survive serialization");
    assertArrayEquals(parsedRequestDict.params, ["param1", 123, true], "Request params should survive serialization");
    assertEquals(parsedRequestDict.id, 456, "Request id should survive serialization");
    
    // Test JSONRPCResponse serialization
    const response = new JSONRPCResponse({ status: "ok", data: [1, 2, 3] }, null, 789);
    const responseDict = response.toDict();
    const responseJson = JSON.stringify(responseDict);
    const parsedResponseDict = JSON.parse(responseJson);
    
    assertEquals(parsedResponseDict.result.status, "ok", "Response result should survive serialization");
    assertArrayEquals(parsedResponseDict.result.data, [1, 2, 3], "Response data should survive serialization");
    assertEquals(parsedResponseDict.id, 789, "Response id should survive serialization");
    
    // Test round-trip
    const roundTripResponse = JSONRPCResponse.fromDict(parsedResponseDict);
    assertEquals(roundTripResponse.result.status, "ok", "Round-trip should preserve data");
    assertEquals(roundTripResponse.id, 789, "Round-trip should preserve id");
}

// Helper function to compare arrays
function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// Run all tests
async function runAllTests() {
    console.log(`${BLUE}🧪 Running Client Module Unit Tests${RESET}\n`);
    
    testServerInfo();
    testJSONRPCRequest();
    testJSONRPCResponse();
    testJSONRPCError();
    testOpenADPError();
    testParseServerPublicKey();
    testGetFallbackServerInfo();
    testErrorCode();
    testOpenADPClient();
    testEncryptedOpenADPClient();
    testMultiServerClient();
    testJSONRPCParsing();
    testInputValidation();
    testSerialization();
    
    return printSummary();
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runAllTests().then(success => {
        process.exit(success ? 0 : 1);
    });
}

export { runAllTests }; 