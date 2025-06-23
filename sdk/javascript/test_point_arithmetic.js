import { Point2D, pointMul, pointAdd, expand, unexpand } from './src/crypto.js';

console.log('Testing basic point arithmetic...');

const G = new Point2D(
    55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

console.log('Generator point G:', G.toString());

// Test: 2*G + 3*G should equal 5*G
const twoG = unexpand(pointMul(2n, expand(G)));
const threeG = unexpand(pointMul(3n, expand(G)));
const fiveG = unexpand(pointMul(5n, expand(G)));

console.log('2*G:', twoG.toString());
console.log('3*G:', threeG.toString());
console.log('5*G:', fiveG.toString());

// Add 2*G + 3*G
const sum = unexpand(pointAdd(expand(twoG), expand(threeG)));
console.log('2*G + 3*G:', sum.toString());
console.log('Addition correct:', fiveG.equals(sum));

// Test with the weights from our Lagrange interpolation
const w0 = 2n;
const w1 = 7237005577332262213973186563042994240857116359379907606001950938285454250988n; // -1 mod Q

console.log('\nTesting Lagrange weights...');
console.log('w0 =', w0);
console.log('w1 =', w1);
console.log('w1 mod Q =', w1 % 7237005577332262213973186563042994240857116359379907606001950938285454250989n);

// Verify that w1 is indeed -1 mod Q
const Q = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
const negativeOne = ((-1n) % Q + Q) % Q;
console.log('(-1) mod Q =', negativeOne);
console.log('w1 equals (-1) mod Q:', w1 === negativeOne);
