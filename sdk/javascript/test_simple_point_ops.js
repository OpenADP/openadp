import { Point2D, pointMul, pointAdd, expand, unexpand } from './src/crypto.js';

console.log('Testing very basic point operations...');

const G = new Point2D(
    55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

// Test 1: G + G should equal 2*G
const G_plus_G = unexpand(pointAdd(expand(G), expand(G)));
const twoG = unexpand(pointMul(2n, expand(G)));

console.log('G + G:', G_plus_G.toString());
console.log('2*G:  ', twoG.toString());
console.log('G + G equals 2*G:', G_plus_G.equals(twoG));

// Test 2: 1*G should equal G
const oneG = unexpand(pointMul(1n, expand(G)));
console.log('\n1*G equals G:', oneG.equals(G));

// Test 3: 0*G should be identity point
const zeroG = unexpand(pointMul(0n, expand(G)));
console.log('\n0*G:', zeroG.toString());

// Test 4: Check if point is on curve
import { isValidPoint } from './src/crypto.js';
console.log('\nG is valid point:', isValidPoint(G));
console.log('2*G is valid point:', isValidPoint(twoG));
