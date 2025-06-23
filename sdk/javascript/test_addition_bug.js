import { Point2D, pointMul, pointAdd, expand, unexpand } from './src/crypto.js';

console.log('Debugging point addition...');

const G = new Point2D(
    55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n
);

// Compute points step by step
const twoG = unexpand(pointMul(2n, expand(G)));
const threeG = unexpand(pointMul(3n, expand(G)));
const fiveG = unexpand(pointMul(5n, expand(G)));

console.log('2*G:', twoG.toString());
console.log('3*G:', threeG.toString());
console.log('5*G:', fiveG.toString());

// Try the addition
const sum = unexpand(pointAdd(expand(twoG), expand(threeG)));
console.log('2*G + 3*G:', sum.toString());

// Let's also try a different approach: G + G + G + G + G
let accumulated = expand(G);
for (let i = 1; i < 5; i++) {
    accumulated = pointAdd(accumulated, expand(G));
}
const fiveG_accumulated = unexpand(accumulated);
console.log('G+G+G+G+G:', fiveG_accumulated.toString());

console.log('5*G equals accumulated:', fiveG.equals(fiveG_accumulated));
console.log('5*G equals 2*G+3*G:', fiveG.equals(sum));

// Let's try 2*(2*G) + G = 5*G
const fourG = unexpand(pointMul(2n, expand(twoG)));
const fourG_plus_G = unexpand(pointAdd(expand(fourG), expand(G)));
console.log('4*G + G:', fourG_plus_G.toString());
console.log('4*G + G equals 5*G:', fiveG.equals(fourG_plus_G));
