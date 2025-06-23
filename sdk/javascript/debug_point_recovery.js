import { ShamirSecretSharing, recoverPointSecret, PointShare, Point2D } from './src/crypto.js';

console.log('Testing point recovery with known values...');

// Create a known secret point
const secretPoint = new Point2D(
    12345n,
    67890n
);

console.log('Original secret point:', secretPoint.toString());

// Create point shares (simulating what servers would return)
const pointShares = [
    new PointShare(1, secretPoint),
    new PointShare(2, secretPoint), 
    new PointShare(3, secretPoint)
];

console.log('\nPoint shares:');
for (let i = 0; i < pointShares.length; i++) {
    console.log(`  Share ${i+1}: x=${pointShares[i].x}, point=${pointShares[i].point.toString()}`);
}

// Recover the secret point
console.log('\nRecovering secret point...');
const recoveredPoint = recoverPointSecret(pointShares.slice(0, 2)); // Use only 2 shares

console.log('Recovered point:', recoveredPoint.toString());
console.log('Match:', secretPoint.equals(recoveredPoint));
