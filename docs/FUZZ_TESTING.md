# OpenADP Fuzz Testing Suite

This document describes the comprehensive fuzz testing implemented for OpenADP to ensure robustness and security of the distributed encryption system.

## Overview

Fuzz testing (fuzzing) is a software testing technique that provides invalid, unexpected, or random data as inputs to find crashes, security vulnerabilities, and edge cases. OpenADP implements extensive fuzz testing across three critical layers:

1. **Server Business Logic** (`pkg/server/`)
2. **Cryptographic Operations** (`pkg/crypto/`)  
3. **HTTP/JSON-RPC APIs** (`cmd/openadp-server/`)

## Why Fuzz Testing for OpenADP?

OpenADP handles sensitive cryptographic operations and serves as a distributed trust network. Fuzz testing is crucial because:

- **Security-Critical**: Cryptographic bugs can compromise the entire system
- **Distributed System**: Edge cases in one server can affect the entire network
- **User Input**: APIs receive untrusted input from clients
- **Complex Math**: Elliptic curve operations are prone to edge cases
- **JSON-RPC**: Parsing and validation need robust error handling

## Test Structure

### 1. Server Business Logic Fuzzing (`pkg/server/server_fuzz_test.go`)

Tests the core business logic functions that handle secret sharing and recovery:

#### Input Validation Fuzzing
- `FuzzRegisterInputs`: Tests parameter validation for secret registration
- `FuzzRecoverInputs`: Tests parameter validation for secret recovery

#### End-to-End Workflow Fuzzing  
- `FuzzRegisterSecretE2E`: Complete secret registration flow with database
- `FuzzRecoverSecretE2E`: Complete secret recovery flow with database

#### Component Fuzzing
- `FuzzPointValid`: Point validation logic
- `FuzzServerInfo`: Server information generation
- `FuzzEcho`: Simple echo functionality
- `FuzzListBackups`: Backup listing functionality

#### Data Handling Fuzzing
- `FuzzJSONSerialization`: JSON marshaling/unmarshaling of server types
- `FuzzConcurrentAccess`: Concurrent database operations

### 2. Cryptographic Fuzzing (`pkg/crypto/crypto_fuzz_test.go`)

Tests the cryptographic primitives that secure the entire system:

#### Point Operations
- `FuzzPoint2D`: 2D point creation and validation
- `FuzzPoint4D`: Extended 4D point operations
- `FuzzPointAdd`: Edwards curve point addition
- `FuzzScalarMult`: Scalar multiplication operations
- `FuzzPointConversions`: Conversions between point formats

#### Key Operations
- `FuzzX25519Operations`: X25519 key generation and shared secrets
- `FuzzHashFunctions`: Hash function implementations
- `FuzzRandomBytes`: Random number generation

#### Mathematical Operations
- `FuzzBigIntOperations`: Big integer arithmetic and modular operations

### 3. API Endpoint Fuzzing (`cmd/openadp-server/server_api_fuzz_test.go`)

Tests the HTTP/JSON-RPC interface that clients interact with:

#### Protocol Fuzzing
- `FuzzJSONRPCRequest`: Malformed JSON-RPC requests
- `FuzzHTTPMethods`: Different HTTP methods and headers
- `FuzzParameterTypes`: Wrong parameter types and counts

#### Method-Specific Fuzzing
- `FuzzEchoMethod`: Echo method with various inputs
- `FuzzRegisterSecretMethod`: Secret registration API
- `FuzzRecoverSecretMethod`: Secret recovery API  
- `FuzzListBackupsMethod`: Backup listing API

#### Infrastructure Fuzzing
- `FuzzConcurrentRequests`: Concurrent API requests
- `FuzzLargePayloads`: Large request handling
- `FuzzHealthEndpoint`: Health check endpoint

## Running Fuzz Tests

### Quick Tests (CI-Friendly)
```bash
make fuzz-quick
```
Runs each fuzz test for 10 seconds - good for continuous integration.

### Component-Specific Testing
```bash
make fuzz-server    # Server business logic
make fuzz-crypto    # Cryptographic operations  
make fuzz-api       # HTTP/JSON-RPC APIs
```

### Comprehensive Testing
```bash
make fuzz-all       # All tests with moderate duration
make fuzz-extended  # Extended 5-minute runs
```

### Custom Testing
```bash
make fuzz-custom FUZZ=FuzzRegisterInputs PACKAGE=./pkg/server DURATION=30s
```

### Coverage Analysis
```bash
make fuzz-coverage  # Generate HTML coverage reports
```

## Test Design Principles

### 1. Input Diversity
Each fuzz function includes diverse seed inputs:
- Valid inputs (happy path)
- Empty/null inputs
- Oversized inputs
- Malformed inputs
- Edge case values (max int64, negative numbers, etc.)

### 2. Crash Prevention
All fuzz tests ensure functions don't panic on any input:
```go
// Should not panic with any inputs
result := SomeFunction(fuzzedInput)
```

### 3. Invariant Checking
Tests verify important properties are maintained:
```go
if len(hash) != 32 {
    t.Errorf("Hash length %d != 32", len(hash))
}
```

### 4. Resource Management
Each test iteration uses temporary resources:
```go
dbPath := fmt.Sprintf("fuzz_test_%d.db", rand.Int())
defer os.Remove(dbPath)
```

### 5. Error Tolerance
Tests distinguish between expected and unexpected errors:
```go
if err != nil {
    // Some inputs may be invalid, that's expected
    return  
}
```

## Discovered Issues and Mitigations

### Common Issue Categories

1. **Input Validation Bypass**: Oversized inputs bypassing length checks
2. **Integer Overflow**: Large numbers causing arithmetic issues
3. **Null Pointer Dereference**: Missing nil checks on point coordinates
4. **Resource Leaks**: Database connections not properly closed
5. **Race Conditions**: Concurrent access to shared resources

### Mitigation Strategies

1. **Comprehensive Bounds Checking**: All inputs validated against constants
2. **Safe Arithmetic**: Big integer math prevents overflows
3. **Null Safety**: Explicit nil checks before operations
4. **Resource Cleanup**: Defer statements ensure cleanup
5. **Synchronized Access**: Proper locking for shared resources

## Integration with CI/CD

### GitHub Actions Integration
```yaml
- name: Run Fuzz Tests
  run: make fuzz-quick
```

### Coverage Requirements
- Server logic: >95% code coverage with fuzz tests
- Crypto operations: >98% code coverage with fuzz tests
- API endpoints: >90% code coverage with fuzz tests

## Corpus Management

Go's fuzzing automatically builds a corpus of interesting inputs that trigger edge cases. These are stored in `testdata/fuzz/` directories:

```
testdata/fuzz/FuzzRegisterInputs/
├── 001-malformed-json
├── 002-oversized-uid  
├── 003-negative-numbers
└── ...
```

### Corpus Sharing
Teams can share interesting fuzz inputs by committing them to the repository.

## Performance Considerations

### Test Duration Guidelines
- **CI/Quick**: 10 seconds per test (finds obvious issues)
- **Development**: 1-2 minutes per test (finds most issues)  
- **Extended**: 5+ minutes per test (finds rare edge cases)
- **Release**: 30+ minutes per test (comprehensive validation)

### Resource Usage
Fuzz tests create temporary databases and can be memory-intensive:
- Monitor memory usage during extended runs
- Clean up with `make fuzz-clean` to remove artifacts

## Security Implications

### Critical Test Areas

1. **Authentication Bypass**: Malformed auth codes
2. **Cryptographic Bypass**: Invalid curve points
3. **Injection Attacks**: SQL injection through parameters
4. **Denial of Service**: Large payloads causing resource exhaustion
5. **State Corruption**: Concurrent operations corrupting data

### Threat Model Coverage

- ✅ **Malicious Client**: API fuzzing covers malformed requests
- ✅ **Corrupt Data**: Crypto fuzzing handles invalid mathematical objects
- ✅ **Resource Exhaustion**: Large payload and concurrent request testing
- ✅ **Edge Case Exploitation**: Comprehensive input space exploration

## Best Practices

### Writing New Fuzz Tests

1. **Start Simple**: Begin with basic input validation
2. **Add Complexity**: Progress to end-to-end workflows
3. **Include Edge Cases**: Test boundary conditions explicitly
4. **Verify Invariants**: Check important properties hold
5. **Document Findings**: Note any discovered issues

### Example Template
```go
func FuzzNewFunction(f *testing.F) {
    // Seed with diverse inputs
    f.Add("valid input")
    f.Add("")
    f.Add(strings.Repeat("x", 10000))
    
    f.Fuzz(func(t *testing.T, input string) {
        // Call function - should not panic
        result := NewFunction(input)
        
        // Verify invariants
        if result == nil && len(input) > 0 {
            t.Error("Expected non-nil result for non-empty input")
        }
    })
}
```

## Monitoring and Alerts

### Continuous Monitoring
- Daily fuzz test runs on CI
- Alert on new crashes or hangs
- Track code coverage trends

### Issue Response
1. **Immediate**: Fix crashes that could cause DoS
2. **High Priority**: Fix authentication or crypto bypasses  
3. **Medium Priority**: Fix incorrect error handling
4. **Low Priority**: Improve edge case handling

## Future Enhancements

### Planned Improvements
1. **Client-Side Fuzzing**: Fuzz client responses to malformed server data
2. **Protocol Fuzzing**: Network-level protocol fuzzing
3. **State Machine Fuzzing**: Test complex multi-step workflows
4. **Property-Based Testing**: Combine with QuickCheck-style properties

### Integration Opportunities
1. **AFL++ Integration**: Use AFL++ for deeper fuzzing
2. **libFuzzer Integration**: Leverage LLVM's libFuzzer
3. **OSS-Fuzz**: Submit to Google's OSS-Fuzz for continuous fuzzing

## Conclusion

OpenADP's comprehensive fuzz testing suite provides confidence in the system's robustness against malformed inputs, edge cases, and potential security vulnerabilities. Regular fuzzing helps maintain the high security standards required for a distributed cryptographic system.

For questions or contributions to the fuzz testing suite, please see the contributing guidelines. 