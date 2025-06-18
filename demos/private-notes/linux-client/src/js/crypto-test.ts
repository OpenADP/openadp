import { 
    encryptData, 
    decryptData, 
    generateKey, 
    generateNonce,
    hashContent,
    isChaCha20Poly1305Supported 
} from '../../shared/crypto-utils.js';

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
 * Test ChaCha20-Poly1305 encryption/decryption
 */
async function testChaCha20Poly1305(): Promise<TestResult[]> {
    const results: TestResult[] = [];
    
    try {
        // Test 1: Check browser support
        const supported = await isChaCha20Poly1305Supported();
        results.push({
            success: supported,
            message: 'ChaCha20-Poly1305 Browser Support',
            details: supported ? 'Supported in this browser' : 'Not supported - will fallback to AES-GCM'
        });

        // Test 2: Generate key and nonce
        const key = await generateKey();
        const nonce = generateNonce();
        
        results.push({
            success: key.byteLength === 32,
            message: 'Key Generation',
            details: `Generated ${key.byteLength}-byte key`
        });
        
        results.push({
            success: nonce.byteLength === 12,
            message: 'Nonce Generation', 
            details: `Generated ${nonce.byteLength}-byte nonce`
        });

        // Test 3: Encrypt test data
        const testData = 'Hello, OpenADP! This is a test of ChaCha20-Poly1305 encryption.';
        const metadata = { version: 1, timestamp: Date.now() };
        
        const encrypted = await encryptData(testData, key, metadata);
        
        results.push({
            success: encrypted.encryptedData.byteLength > 0,
            message: 'Data Encryption',
            details: `Encrypted ${testData.length} bytes to ${encrypted.encryptedData.byteLength} bytes`
        });

        // Test 4: Decrypt test data
        const decrypted = await decryptData(encrypted, key);
        
        results.push({
            success: decrypted === testData,
            message: 'Data Decryption',
            details: `Decrypted: "${decrypted.substring(0, 50)}${decrypted.length > 50 ? '...' : ''}"`
        });

        // Test 5: Test with different metadata
        const metadata2 = { version: 2, timestamp: Date.now() + 1000 };
        const encrypted2 = await encryptData(testData, key, metadata2);
        
        // Should fail to decrypt with wrong metadata
        try {
            await decryptData(encrypted2, key, metadata);
            results.push({
                success: false,
                message: 'Metadata Authentication',
                details: 'Should have failed with wrong metadata'
            });
        } catch (error) {
            results.push({
                success: true,
                message: 'Metadata Authentication',
                details: 'Correctly rejected wrong metadata'
            });
        }

        // Test 6: Test with wrong key
        const wrongKey = await generateKey();
        try {
            await decryptData(encrypted, wrongKey);
            results.push({
                success: false,
                message: 'Key Authentication',
                details: 'Should have failed with wrong key'
            });
        } catch (error) {
            results.push({
                success: true,
                message: 'Key Authentication',
                details: 'Correctly rejected wrong key'
            });
        }

        // Test 7: Test empty data
        const emptyEncrypted = await encryptData('', key, metadata);
        const emptyDecrypted = await decryptData(emptyEncrypted, key, metadata);
        
        results.push({
            success: emptyDecrypted === '',
            message: 'Empty Data Handling',
            details: 'Successfully handled empty string'
        });

    } catch (error) {
        results.push({
            success: false,
            message: 'Crypto Test Failed',
            error: error as Error
        });
    }
    
    return results;
}

/**
 * Test content hashing functionality
 */
async function testContentHashing(): Promise<TestResult[]> {
    const results: TestResult[] = [];
    
    try {
        // Test 1: Basic hashing
        const content1 = 'This is a test note content.';
        const hash1 = await hashContent(content1);
        
        results.push({
            success: hash1.length === 64, // SHA-256 hex is 64 characters
            message: 'Content Hash Generation',
            details: `Hash: ${hash1}`
        });

        // Test 2: Same content produces same hash
        const hash1b = await hashContent(content1);
        
        results.push({
            success: hash1 === hash1b,
            message: 'Hash Consistency',
            details: 'Same content produces identical hash'
        });

        // Test 3: Different content produces different hash
        const content2 = 'This is a different test note content.';
        const hash2 = await hashContent(content2);
        
        results.push({
            success: hash1 !== hash2,
            message: 'Hash Uniqueness',
            details: `Different hashes: ${hash1 !== hash2}`
        });

        // Test 4: Empty content
        const emptyHash = await hashContent('');
        
        results.push({
            success: emptyHash.length === 64,
            message: 'Empty Content Hash',
            details: `Empty hash: ${emptyHash}`
        });

        // Test 5: Unicode content
        const unicodeContent = '🔐 Unicode test: 日本語 emoji 🚀';
        const unicodeHash = await hashContent(unicodeContent);
        
        results.push({
            success: unicodeHash.length === 64,
            message: 'Unicode Content Hash',
            details: `Unicode hash: ${unicodeHash}`
        });

        // Test 6: Large content
        const largeContent = 'A'.repeat(10000);
        const largeHash = await hashContent(largeContent);
        
        results.push({
            success: largeHash.length === 64,
            message: 'Large Content Hash',
            details: `Large content (${largeContent.length} chars) hash: ${largeHash}`
        });

    } catch (error) {
        results.push({
            success: false,
            message: 'Hash Test Failed',
            error: error as Error
        });
    }
    
    return results;
}

/**
 * Initialize crypto tests
 */
function initCryptoTests(): void {
    const cryptoBtn = document.getElementById('test-crypto-btn');
    const hashBtn = document.getElementById('test-hash-btn');

    if (cryptoBtn) {
        cryptoBtn.addEventListener('click', async () => {
            cryptoBtn.textContent = 'Testing...';
            (cryptoBtn as HTMLButtonElement).disabled = true;
            
            try {
                const results = await testChaCha20Poly1305();
                displayResults('test-results', results);
            } finally {
                cryptoBtn.textContent = 'Test ChaCha20-Poly1305';
                (cryptoBtn as HTMLButtonElement).disabled = false;
            }
        });
    }

    if (hashBtn) {
        hashBtn.addEventListener('click', async () => {
            hashBtn.textContent = 'Testing...';
            (hashBtn as HTMLButtonElement).disabled = true;
            
            try {
                const results = await testContentHashing();
                displayResults('test-results', results);
            } finally {
                hashBtn.textContent = 'Test Content Hashing';
                (hashBtn as HTMLButtonElement).disabled = false;
            }
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCryptoTests);
} else {
    initCryptoTests();
} 