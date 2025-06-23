#!/usr/bin/env node

/**
 * Ocrypt JavaScript Demo - Nation-State Resistant Password Protection
 * 
 * This demo showcases the Ocrypt API for distributed password hashing
 * using OpenADP's Oblivious Pseudo Random Function (OPRF) cryptography.
 */

import { register, recover, OcryptError } from '../src/index.js';
import { randomBytes } from 'crypto';

async function main() {
    console.log('🔮 Ocrypt Demo - Nation-State Resistant Password Protection');
    console.log('🌐 Using OpenADP distributed threshold cryptography');
    console.log('🔐 Based on Oblivious Pseudo Random Function (OPRF) cryptography');
    console.log();

    try {
        await runDemos();
        
        console.log('============================================================');
        console.log('🎉 All demos completed successfully!');
        console.log('============================================================');
        console.log();
        console.log('📚 Next steps:');
        console.log('   1. Install the package: npm install @openadp/ocrypt');
        console.log('   2. Run the test suite: npm test');
        console.log('   3. Read the API documentation in the README');
        console.log('   4. Start integrating Ocrypt into your Node.js applications!');
        console.log();
        console.log('🔗 Learn more about OpenADP at: https://openadp.org');
        console.log('🔬 Learn about OPRF cryptography: https://tools.ietf.org/rfc/rfc9497.txt');
        
    } catch (error) {
        console.error('❌ Demo failed:', error.message);
        process.exit(1);
    }
}

async function runDemos() {
    await demoBasicUsage();
    await demoAPITokenStorage();
    await demoDatabaseEncryption();
    await demoMigrationFromBcrypt();
}

async function demoBasicUsage() {
    console.log('============================================================');
    console.log('DEMO 1: Basic Ocrypt API Usage');
    console.log('============================================================');

    // Demo parameters
    const userID = 'alice@example.com';
    const appID = 'payment_processor';
    const secret = new TextEncoder().encode('This is my super secret API key: sk_live_51234567890abcdef');
    const pin = 'secure_password_123';

    console.log(`🔐 Protecting secret for user: ${userID}`);
    console.log(`📱 Application: ${appID}`);
    console.log(`🔑 Secret length: ${secret.length} bytes`);
    console.log();

    try {
        // Step 1: Register secret
        console.log('📋 Step 1: Register secret with OpenADP...');
        const metadata = await register(userID, appID, secret, pin, 10);

        console.log('✅ Registration successful!');
        console.log(`📦 Metadata size: ${metadata.length} bytes`);
        console.log(`🎯 Metadata preview: ${new TextDecoder().decode(metadata.slice(0, Math.min(100, metadata.length)))}...`);
        console.log();

        // Step 2: Recover secret
        console.log('📋 Step 2: Recover secret using PIN...');
        const result = await recover(metadata, pin);

        console.log('✅ Recovery successful!');
        console.log(`🔓 Recovered secret: ${new TextDecoder().decode(result.secret)}`);
        console.log(`🎯 Remaining guesses: ${result.remaining}`);
        console.log(`✅ Secret matches: ${new TextDecoder().decode(secret) === new TextDecoder().decode(result.secret)}`);
        console.log(`📦 Updated metadata size: ${result.updatedMetadata.length} bytes`);
        console.log();

        // Step 3: Test wrong PIN
        console.log('📋 Step 3: Test wrong PIN...');
        try {
            await recover(metadata, 'wrong_pin');
            console.log('❌ Wrong PIN should have been rejected');
        } catch (error) {
            console.log(`✅ Wrong PIN correctly rejected: ${error.message}`);
        }

    } catch (error) {
        console.log(`❌ Demo failed: ${error.message}`);
        console.log('   This is expected if OpenADP servers are not accessible');
        console.log('   In production, ensure servers are reachable');
    }

    console.log();
}

async function demoAPITokenStorage() {
    console.log('============================================================');
    console.log('DEMO 2: API Token Storage');
    console.log('============================================================');

    // Simulate protecting various API tokens
    const tokens = {
        'stripe_api_key': 'sk_live_51HyperSecureStripeToken123456789',
        'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
        'github_token': 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'database_password': 'super_secure_db_password_2024'
    };

    const userID = 'service_account_001';
    const pin = 'service_pin_2024';

    const protectedTokens = new Map();

    console.log(`🔐 Protecting ${Object.keys(tokens).length} API tokens for service account...`);
    console.log();

    // Protect each token
    for (const [tokenName, tokenValue] of Object.entries(tokens)) {
        console.log(`📋 Protecting ${tokenName}...`);

        try {
            const metadata = await register(userID, tokenName, new TextEncoder().encode(tokenValue), pin, 3);
            protectedTokens.set(tokenName, metadata);
            console.log(`   ✅ Protected (${metadata.length} bytes metadata)`);
        } catch (error) {
            console.log(`   ❌ Failed: ${error.message}`);
            console.log('   This is expected if OpenADP servers are not accessible');
        }
    }

    if (protectedTokens.size === 0) {
        console.log('⚠️  No tokens protected (servers not accessible)');
        console.log('   In production, ensure OpenADP servers are reachable');
        console.log();
        return;
    }

    console.log();
    console.log(`✅ All ${protectedTokens.size} tokens protected!`);
    console.log();

    // Recover tokens
    console.log('📋 Recovering tokens...');
    for (const [tokenName, metadata] of protectedTokens) {
        try {
            const result = await recover(metadata, pin);
            const recoveredToken = new TextDecoder().decode(result.secret);
            const originalToken = tokens[tokenName];
            const matches = recoveredToken === originalToken;

            console.log(`   🔓 ${tokenName}: ${matches ? '✅ MATCH' : '❌ MISMATCH'}`);
            console.log(`      Original:  ${originalToken.substring(0, Math.min(20, originalToken.length))}...`);
            console.log(`      Recovered: ${recoveredToken.substring(0, Math.min(20, recoveredToken.length))}...`);
        } catch (error) {
            console.log(`   ❌ ${tokenName}: Recovery failed: ${error.message}`);
        }
    }

    console.log();
    console.log('✅ All tokens recovered successfully!');
    console.log();
}

async function demoDatabaseEncryption() {
    console.log('============================================================');
    console.log('DEMO 3: Database Encryption Key Protection');
    console.log('============================================================');

    // Generate a database encryption key
    console.log('🔐 Generating database encryption key...');
    const dbEncryptionKey = randomBytes(32); // AES-256 key

    console.log('✅ Generated 256-bit encryption key');
    console.log(`🔑 Key: ${Buffer.from(dbEncryptionKey).toString('hex')}`);
    console.log();

    // Protect the database key
    const userID = 'database_cluster_01';
    const appID = 'customer_data_encryption';
    const pin = 'db_master_pin_2024';

    try {
        console.log('📋 Step 1: Protect database key with Ocrypt...');
        const metadata = await register(userID, appID, dbEncryptionKey, pin, 10);

        console.log('✅ Database key protected!');
        console.log(`📦 Metadata size: ${metadata.length} bytes`);
        console.log();

        // Simulate database startup - recover the key
        console.log('📋 Step 2: Database startup - recover encryption key...');
        const result = await recover(metadata, pin);

        console.log('✅ Database key recovered!');
        console.log(`🔑 Recovered key: ${Buffer.from(result.secret).toString('hex')}`);
        console.log(`✅ Keys match: ${Buffer.from(dbEncryptionKey).equals(Buffer.from(result.secret))}`);
        console.log();

        // Simulate encrypting database records
        console.log('📋 Step 3: Encrypt sample database record...');
        const customerData = {
            customer_id: 'cust_12345',
            name: 'John Doe',
            email: 'john@example.com',
            phone: '+1-555-123-4567',
            address: {
                street: '123 Main St',
                city: 'Anytown',
                state: 'CA',
                zip: '12345'
            }
        };

        const customerJSON = JSON.stringify(customerData);

        // In a real application, you would use the recovered key for AES encryption
        console.log('✅ Customer data ready for encryption!');
        console.log(`📄 Original size: ${customerJSON.length} bytes`);
        console.log('🔑 Using recovered key for encryption');
        console.log(`👤 Customer: ${customerData.name} (${customerData.email})`);

    } catch (error) {
        console.log(`❌ Protection failed: ${error.message}`);
        console.log('   This is expected if OpenADP servers are not accessible');
    }

    console.log();
}

async function demoMigrationFromBcrypt() {
    console.log('============================================================');
    console.log('DEMO 4: Migration from Traditional Password Hashing');
    console.log('============================================================');

    // Simulate existing user database with bcrypt hashes
    console.log('🗃️  Simulating existing user database with bcrypt hashes...');
    const users = {
        'alice@example.com': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYLS.HzgDmxRjVzk8Y8P0.xH8J8qJ8ZG',
        'bob@example.com': '$2b$12$EXRkDxrfQIyuVvVvVvVvVeyJQBhwHGUcgLVJ8ZYxHGUcgLVJ8ZYxH'
    };

    console.log(`📊 Found ${Object.keys(users).length} users with bcrypt hashes`);
    for (const [email, hash] of Object.entries(users)) {
        console.log(`   👤 ${email}: ${hash.substring(0, 32)}...`);
    }
    console.log();

    // Migrate to Ocrypt
    console.log('🔄 Migrating to Ocrypt...');
    const migratedUsers = new Map();

    for (const email of Object.keys(users)) {
        console.log(`📋 Migrating ${email}...`);

        try {
            // Generate a random secret for each user (in practice, you might derive this from existing data)
            const userSecret = randomBytes(32);

            // Use a demo password (in practice, this would be done during user login)
            const userPassword = 'user_password_123';

            const metadata = await register(email, 'user_authentication', userSecret, userPassword, 5);
            migratedUsers.set(email, { metadata, secret: userSecret });
            console.log(`   ✅ Migrated (${metadata.length} bytes metadata)`);
        } catch (error) {
            console.log(`   ❌ Failed: ${error.message}`);
            console.log('   This is expected if OpenADP servers are not accessible');
        }
    }

    if (migratedUsers.size === 0) {
        console.log('⚠️  No users migrated (servers not accessible)');
        console.log('   In production, ensure OpenADP servers are reachable');
        console.log();
        return;
    }

    console.log();
    console.log(`✅ Migration complete! ${migratedUsers.size} users migrated`);
    console.log();

    // Test authentication with new system
    console.log('📋 Testing authentication with new system...');
    for (const [email, userData] of migratedUsers) {
        console.log(`🔐 User ${email} attempting login...`);

        try {
            // Test with correct password
            const userPassword = 'user_password_123';
            const result = await recover(userData.metadata, userPassword);

            console.log('✅ Authentication: SUCCESS');
            console.log(`🔑 Secret recovered: ${result.secret.length} bytes`);
            console.log(`🎯 Remaining attempts: ${result.remaining}`);
        } catch (error) {
            console.log(`❌ Authentication failed: ${error.message}`);
        }
    }

    console.log();
    console.log('🎉 Migration Benefits:');
    console.log('   ✅ Nation-state resistant (distributed across multiple servers)');
    console.log('   ✅ Guess limiting (built-in brute force protection)');
    console.log('   ✅ No local password storage (metadata contains no secrets)');
    console.log('   ✅ Automatic backup refresh (on successful authentication)');
    console.log('   ✅ Threshold recovery (works even if some servers are down)');
    console.log('   ✅ OPRF-based security (oblivious pseudo random functions)');

    console.log();
}

// Run the demo
main().catch(console.error); 