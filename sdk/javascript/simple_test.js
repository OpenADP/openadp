import { ShamirSecretSharing } from './src/crypto.js';

console.log('Testing byte conversion...');
const testBytes = new Uint8Array([1, 2, 3, 4]);
console.log('Original bytes:', Array.from(testBytes));

const bigInt = ShamirSecretSharing.bytesToBigInt(testBytes);
console.log('As BigInt:', bigInt);

const backToBytes = ShamirSecretSharing.bigIntToBytes(bigInt, 4);
console.log('Back to bytes:', Array.from(backToBytes));

console.log('Match:', Array.from(testBytes).every((b, i) => b === backToBytes[i]));

// Test with small secret sharing
console.log('\nTesting small secret sharing...');
const secret = new Uint8Array([0, 0, 0, 5]); // Simple 5
const shares = ShamirSecretSharing.split(secret, 2, 3);
console.log('Shares:', shares.map(s => ({x: s.x, y: s.y.toString()})));

const recovered = ShamirSecretSharing.recover([shares[0], shares[1]]);
console.log('Recovered:', Array.from(recovered)); 