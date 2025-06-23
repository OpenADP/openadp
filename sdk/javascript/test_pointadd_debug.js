import { pointAdd, pointMul, Point4D, G } from './src/crypto.js';

console.log('=== Systematic pointAdd Debug Test ===');

// Test 1: Point doubling (this should work)
console.log('\n--- Test 1: Point doubling G + G vs 2*G ---');
const g_plus_g = pointAdd(G, G);
const two_g = pointMul(2n, G);
console.log(`G + G:  x=${g_plus_g.x}, y=${g_plus_g.y}`);
console.log(`2*G:    x=${two_g.x}, y=${two_g.y}`);
console.log(`Match:  ${g_plus_g.x === two_g.x && g_plus_g.y === two_g.y ? '✅' : '❌'}`);

// Test 2: Adding different points (2*G + G)
console.log('\n--- Test 2: Adding different points 2*G + G vs 3*G ---');
const two_g_plus_g = pointAdd(two_g, G);
const three_g = pointMul(3n, G);
console.log(`2*G + G: x=${two_g_plus_g.x}, y=${two_g_plus_g.y}`);
console.log(`3*G:     x=${three_g.x}, y=${three_g.y}`);
console.log(`Match:   ${two_g_plus_g.x === three_g.x && two_g_plus_g.y === three_g.y ? '✅' : '❌'}`);

// Test 3: Adding different points (3*G + G)
console.log('\n--- Test 3: Adding different points 3*G + G vs 4*G ---');
const three_g_plus_g = pointAdd(three_g, G);
const four_g = pointMul(4n, G);
console.log(`3*G + G: x=${three_g_plus_g.x}, y=${three_g_plus_g.y}`);
console.log(`4*G:     x=${four_g.x}, y=${four_g.y}`);
console.log(`Match:   ${three_g_plus_g.x === four_g.x && three_g_plus_g.y === four_g.y ? '✅' : '❌'}`);

// Test 4: Adding different points (4*G + G) - this worked before!
console.log('\n--- Test 4: Adding different points 4*G + G vs 5*G ---');
const four_g_plus_g = pointAdd(four_g, G);
const five_g = pointMul(5n, G);
console.log(`4*G + G: x=${four_g_plus_g.x}, y=${four_g_plus_g.y}`);
console.log(`5*G:     x=${five_g.x}, y=${five_g.y}`);
console.log(`Match:   ${four_g_plus_g.x === five_g.x && four_g_plus_g.y === five_g.y ? '✅' : '❌'}`);

// Test 5: The problematic case (2*G + 3*G)
console.log('\n--- Test 5: The problematic case 2*G + 3*G vs 5*G ---');
const two_g_plus_three_g = pointAdd(two_g, three_g);
console.log(`2*G + 3*G: x=${two_g_plus_three_g.x}, y=${two_g_plus_three_g.y}`);
console.log(`5*G:       x=${five_g.x}, y=${five_g.y}`);
console.log(`Match:     ${two_g_plus_three_g.x === five_g.x && two_g_plus_three_g.y === five_g.y ? '✅' : '❌'}`);

// Test 6: Let's also test if pointMul itself is consistent
console.log('\n--- Test 6: pointMul consistency check ---');
const five_g_alt = pointMul(5n, G);
console.log(`pointMul(5, G):     x=${five_g.x}, y=${five_g.y}`);
console.log(`pointMul(5, G) alt: x=${five_g_alt.x}, y=${five_g_alt.y}`);
console.log(`pointMul consistent: ${five_g.x === five_g_alt.x && five_g.y === five_g_alt.y ? '✅' : '❌'}`);

// Test 7: Let's test a completely different scalar multiplication
console.log('\n--- Test 7: Testing larger scalar multiplication ---');
const large_scalar = 12345n;
const large_result1 = pointMul(large_scalar, G);
const large_result2 = pointMul(large_scalar, G);
console.log(`pointMul(${large_scalar}, G) consistent: ${large_result1.x === large_result2.x && large_result1.y === large_result2.y ? '✅' : '❌'}`);

console.log('\n=== Analysis ===');
console.log('If pointAdd works for some cases but not others, we need to identify the pattern.');
console.log('If pointMul is inconsistent, that suggests randomness or state issues.');
console.log('If pointMul is consistent but wrong, the issue is in the algorithm.'); 