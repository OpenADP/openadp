import { ShamirSecretSharing, recoverPointSecret, PointShare, Point2D, pointMul, expand, unexpand } from './src/crypto.js';

console.log('Testing proper point recovery workflow...');

// Step 1: Create a secret
const secret = 12345n;
console.log('Secret:', secret);

// Step 2: Create scalar shares using Shamir secret sharing
const shares = ShamirSecretSharing.splitSecret(secret, 2, 3);
console.log('\nScalar shares:');
for (let i = 0; i < shares.length; i++) {
    const [x, y] = shares[i];
    console.log(`  Share ${i+1}: x=${x}, y=${y}`);
}

// Step 3: Simulate what servers do - multiply each scalar share by a base point B
// Let's use a simple point as B (this would be r*U in the real system)
const B = new Point2D(
    55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n
); // This is the generator point

console.log('\nBase point B:', B.toString());

// Create point shares: each server computes si * B
const pointShares = [];
for (let i = 0; i < shares.length; i++) {
    const [x, y] = shares[i];
    const siB4D = pointMul(y, expand(B)); // si * B
    const siB = unexpand(siB4D);
    pointShares.push(new PointShare(x, siB));
    console.log(`  Point share ${i+1}: x=${x}, point=${siB.toString()}`);
}

// Step 4: Recover the secret point using point-based recovery
console.log('\nRecovering secret point...');
const recoveredSB = recoverPointSecret(pointShares.slice(0, 2)); // Use only 2 shares

// Step 5: Verify by computing expected result directly
const expectedSB4D = pointMul(secret, expand(B)); // secret * B
const expectedSB = unexpand(expectedSB4D);

console.log('\nExpected s*B:', expectedSB.toString());
console.log('Recovered s*B:', recoveredSB.toString());
console.log('Match:', expectedSB.equals(recoveredSB));
