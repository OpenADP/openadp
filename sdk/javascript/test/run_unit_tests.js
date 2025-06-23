#!/usr/bin/env node

import { runAllTests as runCryptoTests } from './test_crypto.js';
import { runAllTests as runKeygenTests } from './test_keygen.js';
import { runAllTests as runClientTests } from './test_client.js';

// Test colors for output
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';

async function runAllUnitTests() {
    console.log(`${BOLD}${CYAN}🧪 OpenADP JavaScript SDK Unit Test Suite${RESET}\n`);
    console.log(`${BLUE}Running comprehensive unit tests for all core modules...${RESET}\n`);
    
    const results = [];
    let totalSuccess = true;
    
    // Run crypto tests
    console.log(`${BOLD}${BLUE}┌─────────────────────────────────────────────┐${RESET}`);
    console.log(`${BOLD}${BLUE}│           CRYPTO MODULE TESTS              │${RESET}`);
    console.log(`${BOLD}${BLUE}└─────────────────────────────────────────────┘${RESET}`);
    
    try {
        const cryptoSuccess = await runCryptoTests();
        results.push({ module: 'Crypto', success: cryptoSuccess });
        totalSuccess = totalSuccess && cryptoSuccess;
    } catch (error) {
        console.log(`${RED}❌ Crypto tests failed with error: ${error.message}${RESET}`);
        results.push({ module: 'Crypto', success: false, error: error.message });
        totalSuccess = false;
    }
    
    console.log(`\n${BLUE}${'='.repeat(60)}${RESET}\n`);
    
    // Run keygen tests
    console.log(`${BOLD}${BLUE}┌─────────────────────────────────────────────┐${RESET}`);
    console.log(`${BOLD}${BLUE}│           KEYGEN MODULE TESTS              │${RESET}`);
    console.log(`${BOLD}${BLUE}└─────────────────────────────────────────────┘${RESET}`);
    
    try {
        const keygenSuccess = await runKeygenTests();
        results.push({ module: 'Keygen', success: keygenSuccess });
        totalSuccess = totalSuccess && keygenSuccess;
    } catch (error) {
        console.log(`${RED}❌ Keygen tests failed with error: ${error.message}${RESET}`);
        results.push({ module: 'Keygen', success: false, error: error.message });
        totalSuccess = false;
    }
    
    console.log(`\n${BLUE}${'='.repeat(60)}${RESET}\n`);
    
    // Run client tests
    console.log(`${BOLD}${BLUE}┌─────────────────────────────────────────────┐${RESET}`);
    console.log(`${BOLD}${BLUE}│           CLIENT MODULE TESTS             │${RESET}`);
    console.log(`${BOLD}${BLUE}└─────────────────────────────────────────────┘${RESET}`);
    
    try {
        const clientSuccess = await runClientTests();
        results.push({ module: 'Client', success: clientSuccess });
        totalSuccess = totalSuccess && clientSuccess;
    } catch (error) {
        console.log(`${RED}❌ Client tests failed with error: ${error.message}${RESET}`);
        results.push({ module: 'Client', success: false, error: error.message });
        totalSuccess = false;
    }
    
    // Print comprehensive summary
    console.log(`\n${BOLD}${CYAN}${'='.repeat(80)}${RESET}`);
    console.log(`${BOLD}${CYAN}                    COMPREHENSIVE TEST SUMMARY${RESET}`);
    console.log(`${BOLD}${CYAN}${'='.repeat(80)}${RESET}\n`);
    
    console.log(`${BOLD}Module Test Results:${RESET}`);
    console.log(`${BLUE}${'─'.repeat(50)}${RESET}`);
    
    let passedModules = 0;
    let totalModules = results.length;
    
    for (const result of results) {
        const status = result.success ? `${GREEN}✅ PASSED${RESET}` : `${RED}❌ FAILED${RESET}`;
        const moduleName = result.module.padEnd(15);
        console.log(`${BOLD}${moduleName}${RESET} │ ${status}`);
        
        if (result.error) {
            console.log(`                │   ${RED}Error: ${result.error}${RESET}`);
        }
        
        if (result.success) {
            passedModules++;
        }
    }
    
    console.log(`${BLUE}${'─'.repeat(50)}${RESET}`);
    
    // Overall summary
    const successRate = Math.round((passedModules / totalModules) * 100);
    console.log(`\n${BOLD}Overall Results:${RESET}`);
    console.log(`  • Total Modules: ${totalModules}`);
    console.log(`  • Passed: ${GREEN}${passedModules}${RESET}`);
    console.log(`  • Failed: ${RED}${totalModules - passedModules}${RESET}`);
    console.log(`  • Success Rate: ${successRate >= 100 ? GREEN : successRate >= 80 ? YELLOW : RED}${successRate}%${RESET}`);
    
    if (totalSuccess) {
        console.log(`\n${GREEN}${BOLD}🎉 ALL UNIT TESTS PASSED! 🎉${RESET}`);
        console.log(`${GREEN}The JavaScript SDK is ready for production use.${RESET}`);
    } else {
        console.log(`\n${RED}${BOLD}⚠️  SOME TESTS FAILED ⚠️${RESET}`);
        console.log(`${RED}Please review the failed tests above and fix any issues.${RESET}`);
        
        // Provide guidance on common issues
        console.log(`\n${YELLOW}Common issues to check:${RESET}`);
        console.log(`  • Missing dependencies (run: npm install)`);
        console.log(`  • Import/export syntax errors`);
        console.log(`  • Cryptographic implementation bugs`);
        console.log(`  • Network connectivity issues`);
        console.log(`  • File permission problems`);
    }
    
    // Test coverage and recommendations
    console.log(`\n${BLUE}${BOLD}Test Coverage Summary:${RESET}`);
    console.log(`${BLUE}${'─'.repeat(40)}${RESET}`);
    console.log(`  ✓ Point arithmetic and curve operations`);
    console.log(`  ✓ Cryptographic hash functions`);
    console.log(`  ✓ Shamir Secret Sharing implementation`);
    console.log(`  ✓ Key derivation and encryption`);
    console.log(`  ✓ Authentication code generation`);
    console.log(`  ✓ JSON-RPC protocol handling`);
    console.log(`  ✓ Client class functionality`);
    console.log(`  ✓ Error handling and validation`);
    console.log(`  ✓ Serialization/deserialization`);
    console.log(`  ✓ Edge case handling`);
    
    if (totalSuccess) {
        console.log(`\n${GREEN}${BOLD}🚀 Next Steps:${RESET}`);
        console.log(`  1. Run integration tests: ${CYAN}npm run test:integration${RESET}`);
        console.log(`  2. Test cross-language compatibility: ${CYAN}python run_all_tests.py${RESET}`);
        console.log(`  3. Test with live servers: ${CYAN}npm run test:live${RESET}`);
        console.log(`  4. Performance benchmarks: ${CYAN}npm run test:performance${RESET}`);
    }
    
    console.log(`\n${CYAN}${'='.repeat(80)}${RESET}\n`);
    
    return totalSuccess;
}

// Handle command line execution
if (import.meta.url === `file://${process.argv[1]}`) {
    runAllUnitTests().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error(`${RED}❌ Test runner failed: ${error.message}${RESET}`);
        console.error(error.stack);
        process.exit(1);
    });
}

export { runAllUnitTests }; 