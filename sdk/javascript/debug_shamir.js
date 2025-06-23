import { ShamirSecretSharing } from './src/crypto.js';

console.log('Testing Shamir secret sharing with small values...');
const secret = 12345n;
const shares = ShamirSecretSharing.splitSecret(secret, 2, 3);

console.log('Secret:', secret);
console.log('Shares:');
for (let i = 0; i < shares.length; i++) {
    const [x, y] = shares[i];
    console.log(`  Share ${i+1}: x=${x}, y=${y}`);
    console.log(`  Share ${i+1} hex: ${BigInt(y).toString(16).padStart(64, '0')}`);
}

// Test recovery
console.log('\nRecovering secret...');
const recovered = ShamirSecretSharing.recoverSecret(shares.slice(0, 2));
console.log('Recovered:', recovered);
console.log('Match:', recovered === Number(secret));
