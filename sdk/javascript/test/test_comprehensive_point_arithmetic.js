#!/usr/bin/env node

import {
    Point2D, Point4D, pointAdd, pointMul, expand, unexpand, isValidPoint
} from '../src/crypto.js';

// Test colors for output
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';
const BLUE = '\x1b[34m';

let testCount = 0;
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
    testCount++;
    if (condition) {
        console.log(`${GREEN}✓${RESET} ${message}`);
        passCount++;
    } else {
        console.log(`${RED}✗${RESET} ${message}`);
        failCount++;
    }
}

function testSection(name) {
    console.log(`\n${BLUE}=== ${name} ===${RESET}`);
}

function printSummary() {
    console.log(`\n${BLUE}=== Test Summary ===${RESET}`);
    console.log(`Total tests: ${testCount}`);
    console.log(`${GREEN}Passed: ${passCount}${RESET}`);
    if (failCount > 0) {
        console.log(`${RED}Failed: ${failCount}${RESET}`);
    }
    console.log(`Success rate: ${Math.round((passCount / testCount) * 100)}%`);
    
    if (failCount === 0) {
        console.log(`${GREEN}🎉 All tests passed!${RESET}`);
        return true;
    } else {
        console.log(`${RED}❌ Some tests failed${RESET}`);
        return false;
    }
}

// Generator point G for Ed25519
const G = new Point4D(
    15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n,
    1n,
    46827403850823179245072216630277197565144205554125654976674165829533817101731n
);

testSection("Basic Point Arithmetic Verification");

function testBasicPointArithmetic() {
    console.log("Testing basic point operations...");
    
    // Test 1: G + G = 2*G (point doubling)
    const G_plus_G = pointAdd(G, G);
    const twoG = pointMul(2n, G);
    assert(G_plus_G.equals(twoG), "G + G should equal 2*G");
    
    // Test 2: 2*G + G = 3*G
    const twoG_plus_G = pointAdd(twoG, G);
    const threeG = pointMul(3n, G);
    assert(twoG_plus_G.equals(threeG), "2*G + G should equal 3*G");
    
    // Test 3: 3*G + G = 4*G
    const threeG_plus_G = pointAdd(threeG, G);
    const fourG = pointMul(4n, G);
    assert(threeG_plus_G.equals(fourG), "3*G + G should equal 4*G");
    
    // Test 4: 4*G + G = 5*G
    const fourG_plus_G = pointAdd(fourG, G);
    const fiveG = pointMul(5n, G);
    assert(fourG_plus_G.equals(fiveG), "4*G + G should equal 5*G");
    
    // Test 5: 2*G + 3*G = 5*G (adding two different points)
    const twoG_plus_threeG = pointAdd(twoG, threeG);
    assert(twoG_plus_threeG.equals(fiveG), "2*G + 3*G should equal 5*G");
    
    // Test 6: Repeated addition: G+G+G+G+G = 5*G
    let repeated = G;
    for (let i = 1; i < 5; i++) {
        repeated = pointAdd(repeated, G);
    }
    assert(repeated.equals(fiveG), "G+G+G+G+G should equal 5*G");
}

testSection("Large Scalar Multiplication Tests");

function testLargeScalarMultiplication() {
    console.log("Testing with large scalars similar to production values...");
    
    // Test with moderately large scalars first
    const scalar100 = 100n;
    const scalar200 = 200n;
    const scalar300 = 300n;
    
    const point100 = pointMul(scalar100, G);
    const point200 = pointMul(scalar200, G);
    const point300 = pointMul(scalar300, G);
    
    // Test: 100*G + 200*G = 300*G
    const sum = pointAdd(point100, point200);
    assert(sum.equals(point300), "100*G + 200*G should equal 300*G");
    
    // Test with larger scalars
    const large1 = 123456789n;
    const large2 = 987654321n;
    const large3 = large1 + large2;
    
    const pointLarge1 = pointMul(large1, G);
    const pointLarge2 = pointMul(large2, G);
    const pointLarge3 = pointMul(large3, G);
    
    const largSum = pointAdd(pointLarge1, pointLarge2);
    assert(largSum.equals(pointLarge3), `${large1}*G + ${large2}*G should equal ${large3}*G`);
}

testSection("Production Values Test - Actual Encryption/Decryption Data");

function testProductionValues() {
    console.log("Testing with actual values from our encryption/decryption scenario...");
    
    // Values from our debug output
    const r = 3049118425107846626202682250554739965777979685585950496049773251056743905841n;
    const bPoint = new Point4D(
        35644252540212755834277131425698747763602219685023877638990596341622414221477n,
        44962653297362858213409581699594858369538377547121025895565970687988390495432n,
        1n,
        0n
    );
    // Compute t = x*y mod P
    const P = 57896044618658097711785492504343953926634992332820282019728792003956564819949n;
    bPoint.t = (bPoint.x * bPoint.y) % P;
    
    // Shares from encryption
    const shares = [
        { x: 1, si: 1759476195616791440814887255098452220095289025314678080712022874099289845256n },
        { x: 2, si: 6663029289265016308163558291665944309211353103071881163376395605283257337140n },
        { x: 3, si: 4329576805580978961539042765190442157470300821449176640038817398181770578035n }
    ];
    
    // Expected server responses (what servers actually returned)
    const expectedServerResponses = [
        {
            x: 1,
            point_x: 56190577226427732570807247345240740373690454566883565679827437526766155912575n,
            point_y: 47798453389747129877313957010420257095583781618752295929915717797464968639789n
        },
        {
            x: 2,
            point_x: 46887637596535289820763105320437236464084394443073357938992975213109908219937n,
            point_y: 41136435946033206363191331121811277796388161905053353023024453442204870065545n
        },
        {
            x: 3,
            point_x: 26727998169641497219916844602958491181977355393848178752945154419061471649774n,
            point_y: 18104246398577860639044126595479773524506120719704729909610218098334368480510n
        }
    ];
    
    console.log("Computing si*B for each share and comparing with server responses...");
    
    for (let i = 0; i < shares.length; i++) {
        const share = shares[i];
        const expected = expectedServerResponses[i];
        
        console.log(`\nTesting share ${share.x} with si = ${share.si}`);
        
        // Compute si * B using our pointMul function
        const computedSiB = pointMul(share.si, bPoint);
        
        // Compare with what the server returned
        const matches = (computedSiB.x === expected.point_x && computedSiB.y === expected.point_y);
        
        if (matches) {
            console.log(`${GREEN}✓${RESET} Share ${share.x}: Our pointMul matches server response`);
            passCount++;
        } else {
            console.log(`${RED}✗${RESET} Share ${share.x}: Our pointMul does NOT match server response`);
            console.log(`  Expected: x=${expected.point_x}, y=${expected.point_y}`);
            console.log(`  Computed: x=${computedSiB.x}, y=${computedSiB.y}`);
            failCount++;
        }
        testCount++;
    }
}

testSection("Point Addition Edge Cases");

function testPointAdditionEdgeCases() {
    console.log("Testing point addition edge cases...");
    
    // Test with the actual B point from production
    const bPoint = new Point4D(
        35644252540212755834277131425698747763602219685023877638990596341622414221477n,
        44962653297362858213409581699594858369538377547121025895565970687988390495432n,
        1n,
        0n
    );
    const P = 57896044618658097711785492504343953926634992332820282019728792003956564819949n;
    bPoint.t = (bPoint.x * bPoint.y) % P;
    
    // Test: B + B = 2*B
    const B_plus_B = pointAdd(bPoint, bPoint);
    const twoB = pointMul(2n, bPoint);
    assert(B_plus_B.equals(twoB), "B + B should equal 2*B");
    
    // Test: 2*B + B = 3*B
    const twoB_plus_B = pointAdd(twoB, bPoint);
    const threeB = pointMul(3n, bPoint);
    assert(twoB_plus_B.equals(threeB), "2*B + B should equal 3*B");
    
    // Test with different points: G + B
    const G_plus_B = pointAdd(G, bPoint);
    const G_scalar = pointMul(1n, G);
    const B_scalar = pointMul(1n, bPoint);
    
    // Verify the addition produces a valid point
    assert(isValidPoint(G_plus_B), "G + B should produce a valid point");
    
    // Test commutativity: G + B = B + G
    const B_plus_G = pointAdd(bPoint, G);
    assert(G_plus_B.equals(B_plus_G), "Point addition should be commutative: G + B = B + G");
}

testSection("Scalar Multiplication Consistency");

function testScalarMultiplicationConsistency() {
    console.log("Testing scalar multiplication consistency...");
    
    // Test that scalar multiplication is consistent with repeated addition
    const testScalars = [2n, 3n, 4n, 5n, 10n, 100n];
    
    for (const scalar of testScalars) {
        // Compute using scalar multiplication
        const scalarResult = pointMul(scalar, G);
        
        // Compute using repeated addition
        let additionResult = G;
        for (let i = 1n; i < scalar; i++) {
            additionResult = pointAdd(additionResult, G);
        }
        
        assert(scalarResult.equals(additionResult), 
               `${scalar}*G should equal G added ${scalar} times`);
    }
}

testSection("Cross-Validation with Known Values");

function testCrossValidation() {
    console.log("Cross-validating with mathematically known relationships...");
    
    // Test: (a + b) * G = a*G + b*G
    const a = 123n;
    const b = 456n;
    const sum = a + b;
    
    const left = pointMul(sum, G);  // (a + b) * G
    const aG = pointMul(a, G);
    const bG = pointMul(b, G);
    const right = pointAdd(aG, bG); // a*G + b*G
    
    assert(left.equals(right), "(a + b)*G should equal a*G + b*G");
    
    // Test: a * (b * G) = (a * b) * G
    const bG_point = pointMul(b, G);
    const left2 = pointMul(a, bG_point);  // a * (b * G)
    const right2 = pointMul(a * b, G);    // (a * b) * G
    
    assert(left2.equals(right2), "a*(b*G) should equal (a*b)*G");
}

// Run all tests
async function runAllTests() {
    console.log(`${BLUE}🧪 Comprehensive Point Arithmetic Test Suite${RESET}`);
    console.log(`${BLUE}================================================${RESET}\n`);
    
    testBasicPointArithmetic();
    testLargeScalarMultiplication();
    testProductionValues();
    testPointAdditionEdgeCases();
    testScalarMultiplicationConsistency();
    testCrossValidation();
    
    const success = printSummary();
    
    if (!success) {
        console.log(`\n${RED}🚨 CRITICAL ISSUES FOUND!${RESET}`);
        console.log(`${RED}The point arithmetic implementation has bugs that need to be fixed.${RESET}`);
        console.log(`${RED}This explains why decryption is failing in production.${RESET}`);
        process.exit(1);
    }
    
    return success;
}

// Run the tests
runAllTests().catch(console.error); 