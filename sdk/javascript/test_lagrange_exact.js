import { modInverse } from './src/crypto.js';

const Q = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

console.log('Testing exact Lagrange interpolation matching Go...');

// Test with the exact shares from our encryption
const shares = [
    { x: 1, y: 3525353663147020241272856632068935517801687451348119500862100732531710177821n },
    { x: 2, y: 2060703915477582739560796739674521018263759462466418284252182799886363292532n }
];

console.log('Input shares:');
shares.forEach((share, i) => {
    console.log(`  Share ${i+1}: x=${share.x}, y=${share.y}`);
});

// Implement the EXACT Go algorithm
const weights = [];

for (let j = 0; j < shares.length; j++) {
    const xj = BigInt(shares[j].x);
    let numerator = 1n;
    let denominator = 1n;
    
    for (let m = 0; m < shares.length; m++) {
        if (j !== m) {
            const xm = BigInt(shares[m].x);
            
            // Go: numerator.Mul(numerator, shareM.X)
            numerator = (numerator * xm) % Q;
            
            // Go: diff := new(big.Int).Sub(shareM.X, shareJ.X)
            // Go: denominator.Mul(denominator, diff)
            let diff = (xm - xj) % Q;
            denominator = (denominator * diff) % Q;
            
            console.log(`Weight ${j}: numerator *= ${xm} -> ${numerator}`);
            console.log(`Weight ${j}: denominator *= (${xm} - ${xj}) = ${diff} -> ${denominator}`);
        }
    }
    
    // Ensure positive
    numerator = (numerator % Q + Q) % Q;
    denominator = (denominator % Q + Q) % Q;
    
    // Go: wi := new(big.Int).Mul(numerator, denominatorInv)
    const denominatorInv = modInverse(denominator, Q);
    const wi = (numerator * denominatorInv) % Q;
    weights[j] = wi;
    
    console.log(`Weight ${j}: final = ${wi}`);
}

console.log('\nFinal weights:', weights);

// Compute weighted sum (for scalar recovery, not point recovery)
let secret = 0n;
for (let i = 0; i < shares.length; i++) {
    const term = (weights[i] * shares[i].y) % Q;
    secret = (secret + term) % Q;
    console.log(`Term ${i}: ${weights[i]} * ${shares[i].y} = ${term}`);
}

secret = (secret % Q + Q) % Q;
console.log('\nRecovered secret:', secret);

// The recovered secret should be the constant term of the polynomial
// Let's verify by creating a simple polynomial and checking
console.log('\n--- Verification ---');
const originalSecret = 12345n; // This should be what we get back
console.log('Expected original secret:', originalSecret);
