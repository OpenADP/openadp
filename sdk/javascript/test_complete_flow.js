import { ShamirSecretSharing, recoverPointSecret, PointShare, Point2D, pointMul, expand, unexpand, modInverse } from './src/crypto.js';

const Q = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

console.log('Testing complete Shamir secret sharing flow...');

// Step 1: Create a known secret
const originalSecret = 12345n;
console.log('Original secret:', originalSecret);

// Step 2: Create shares using our Shamir implementation
const shares = ShamirSecretSharing.splitSecret(originalSecret, 2, 3);
console.log('\nShares created:');
shares.forEach((share, i) => {
    console.log(`  Share ${i+1}: x=${share[0]}, y=${share[1]}`);
});

// Step 3: Recover using scalar Shamir (should work)
const recoveredScalar = ShamirSecretSharing.recoverSecret(shares.slice(0, 2));
console.log('\nScalar recovery result:', recoveredScalar);
console.log('Scalar recovery match:', recoveredScalar === originalSecret || recoveredScalar === Number(originalSecret));

// Step 4: Now test point-based recovery
const G = new Point2D(
    55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

console.log('\nTesting point-based recovery...');

// Create point shares: each share becomes (x, y*G)
const pointShares = [];
for (let i = 0; i < shares.length; i++) {
    const [x, y] = shares[i];
    const yG4D = pointMul(y, expand(G)); // y * G
    const yG = unexpand(yG4D);
    pointShares.push(new PointShare(x, yG));
    console.log(`  Point share ${i+1}: x=${x}, point=${yG.toString()}`);
}

// Recover the secret point using point-based recovery
const recoveredSG = recoverPointSecret(pointShares.slice(0, 2));

// Verify by computing expected result directly
const expectedSG4D = pointMul(originalSecret, expand(G)); // secret * G
const expectedSG = unexpand(expectedSG4D);

console.log('\nExpected secret*G:', expectedSG.toString());
console.log('Recovered secret*G:', recoveredSG.toString());
console.log('Point recovery match:', expectedSG.equals(recoveredSG));
