import { modInverse } from './src/crypto.js';

const Q = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

console.log('Testing Lagrange weight calculation...');

// Test with simple x values: 1, 2
const shares = [
    { x: 1 },
    { x: 2 }
];

console.log('Shares x values:', shares.map(s => s.x));

// Calculate weights using the Go formula
const weights = [];

for (let j = 0; j < shares.length; j++) {
    const xj = BigInt(shares[j].x);
    let numerator = 1n;
    let denominator = 1n;
    
    for (let m = 0; m < shares.length; m++) {
        if (j !== m) {
            const xm = BigInt(shares[m].x);
            
            // Go formula: numerator *= x[m]
            numerator = (numerator * xm) % Q;
            
            // Go formula: denominator *= (x[m] - x[j])
            let diff = (xm - xj) % Q;
            denominator = (denominator * diff) % Q;
            
            console.log(`Weight ${j}: numerator *= ${xm} -> ${numerator}`);
            console.log(`Weight ${j}: denominator *= (${xm} - ${xj}) = ${diff} -> ${denominator}`);
        }
    }
    
    // Ensure positive
    numerator = (numerator % Q + Q) % Q;
    denominator = (denominator % Q + Q) % Q;
    
    console.log(`Weight ${j}: numerator=${numerator}, denominator=${denominator}`);
    
    // Calculate weight
    const denominatorInv = modInverse(denominator, Q);
    const wi = (numerator * denominatorInv) % Q;
    weights[j] = (wi % Q + Q) % Q;
    
    console.log(`Weight ${j}: ${wi}`);
}

console.log('\nFinal weights:', weights);

// For Lagrange interpolation at x=0 with points (1,y1), (2,y2):
// The correct weights should be:
// w0 = 2/(2-1) = 2/1 = 2
// w1 = -1/(-1) = 1
// But we're evaluating at x=0, so it should be:
// w0 = (0-2)/(1-2) = -2/-1 = 2
// w1 = (0-1)/(2-1) = -1/1 = -1

console.log('\nExpected weights for evaluation at x=0:');
console.log('w0 = (0-2)/(1-2) = -2/-1 = 2');
console.log('w1 = (0-1)/(2-1) = -1/1 = -1 (mod Q)');

const expectedW1 = (-1n % Q + Q) % Q;
console.log('w1 mod Q =', expectedW1);
