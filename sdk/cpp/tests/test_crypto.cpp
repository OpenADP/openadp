#include <gtest/gtest.h>
#include "openadp/crypto.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"

namespace openadp {
namespace test {

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test SHA256 hashing
TEST_F(CryptoTest, SHA256Hash) {
    std::string input = "Hello World";
    Bytes data = utils::string_to_bytes(input);
    Bytes hash = crypto::sha256_hash(data);
    
    EXPECT_EQ(hash.size(), 32); // SHA256 produces 32 bytes
    
    // Test known hash value
    std::string expected_hex = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    std::string actual_hex = utils::hex_encode(hash);
    EXPECT_EQ(actual_hex, expected_hex);
}

TEST_F(CryptoTest, SHA256EmptyInput) {
    Bytes empty_data;
    Bytes hash = crypto::sha256_hash(empty_data);
    
    EXPECT_EQ(hash.size(), 32);
    
    // Known SHA256 of empty string
    std::string expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    std::string actual_hex = utils::hex_encode(hash);
    EXPECT_EQ(actual_hex, expected_hex);
}

// Test prefixed function (16-bit length prefix)
TEST_F(CryptoTest, PrefixedFunction) {
    std::string input = "Hello";
    Bytes data = utils::string_to_bytes(input);
    Bytes prefixed = crypto::prefixed(data);
    
    // Should have 2-byte length prefix + data
    EXPECT_EQ(prefixed.size(), 2 + data.size());
    
    // Check little-endian 16-bit length prefix
    uint16_t length = prefixed[0] | (prefixed[1] << 8);
    EXPECT_EQ(length, data.size());
    
    // Check data portion
    Bytes data_portion(prefixed.begin() + 2, prefixed.end());
    EXPECT_EQ(data_portion, data);
}

TEST_F(CryptoTest, PrefixedEmptyData) {
    Bytes empty_data;
    Bytes prefixed = crypto::prefixed(empty_data);
    
    EXPECT_EQ(prefixed.size(), 2); // Just the 2-byte length prefix
    EXPECT_EQ(prefixed[0], 0);
    EXPECT_EQ(prefixed[1], 0);
}

// Test AES-GCM encryption/decryption
TEST_F(CryptoTest, AESGCMEncryptDecrypt) {
    std::string plaintext_str = "This is a secret message";
    Bytes plaintext = utils::string_to_bytes(plaintext_str);
    Bytes key = utils::random_bytes(32); // 256-bit key
    
    auto encrypted = crypto::aes_gcm_encrypt(plaintext, key);
    
    EXPECT_EQ(encrypted.ciphertext.size(), plaintext.size());
    EXPECT_EQ(encrypted.tag.size(), 16); // AES-GCM tag is 16 bytes
    EXPECT_EQ(encrypted.nonce.size(), 12); // Nonce is 12 bytes
    
    Bytes decrypted = crypto::aes_gcm_decrypt(
        encrypted.ciphertext, encrypted.tag, encrypted.nonce, key
    );
    
    EXPECT_EQ(decrypted, plaintext);
    
    std::string decrypted_str = utils::bytes_to_string(decrypted);
    EXPECT_EQ(decrypted_str, plaintext_str);
}

TEST_F(CryptoTest, AESGCMWithAssociatedData) {
    Bytes plaintext = utils::string_to_bytes("Secret data");
    Bytes key = utils::random_bytes(32);
    Bytes associated_data = utils::string_to_bytes("Public header");
    
    auto encrypted = crypto::aes_gcm_encrypt(plaintext, key, associated_data);
    Bytes decrypted = crypto::aes_gcm_decrypt(
        encrypted.ciphertext, encrypted.tag, encrypted.nonce, key, associated_data
    );
    
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(CryptoTest, AESGCMInvalidTag) {
    Bytes plaintext = utils::string_to_bytes("Secret");
    Bytes key = utils::random_bytes(32);
    
    auto encrypted = crypto::aes_gcm_encrypt(plaintext, key);
    
    // Corrupt the tag
    encrypted.tag[0] ^= 0x01;
    
    EXPECT_THROW(
        crypto::aes_gcm_decrypt(encrypted.ciphertext, encrypted.tag, encrypted.nonce, key),
        OpenADPError
    );
}

TEST_F(CryptoTest, AESGCMWrongKey) {
    Bytes plaintext = utils::string_to_bytes("Secret");
    Bytes key1 = utils::random_bytes(32);
    Bytes key2 = utils::random_bytes(32);
    
    auto encrypted = crypto::aes_gcm_encrypt(plaintext, key1);
    
    EXPECT_THROW(
        crypto::aes_gcm_decrypt(encrypted.ciphertext, encrypted.tag, encrypted.nonce, key2),
        OpenADPError
    );
}

// Test HKDF key derivation
TEST_F(CryptoTest, HKDFKeyDerivation) {
    Bytes input_key = utils::random_bytes(32);
    Bytes salt = utils::random_bytes(16);
    Bytes info = utils::string_to_bytes("test info");
    size_t output_length = 32;
    
    Bytes derived = crypto::hkdf_derive(input_key, salt, info, output_length);
    
    EXPECT_EQ(derived.size(), output_length);
    
    // Test deterministic behavior
    Bytes derived2 = crypto::hkdf_derive(input_key, salt, info, output_length);
    EXPECT_EQ(derived, derived2);
    
    // Test different output length
    Bytes derived_longer = crypto::hkdf_derive(input_key, salt, info, 64);
    EXPECT_EQ(derived_longer.size(), 64);
    EXPECT_NE(derived, derived_longer);
}

// Test Ed25519 operations
TEST_F(CryptoTest, Ed25519HashToPoint) {
    Bytes uid = utils::string_to_bytes("user");
    Bytes did = utils::string_to_bytes("device");
    Bytes bid = utils::string_to_bytes("backup");
    Bytes pin = utils::string_to_bytes("1234");
    
    Point4D result = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    EXPECT_TRUE(crypto::Ed25519::is_valid_point(result));
    
    // Test with different inputs should give different results
    Bytes different_pin = utils::string_to_bytes("5678");
    Point4D result2 = crypto::Ed25519::hash_to_point(uid, did, bid, different_pin);
    EXPECT_NE(result.x, result2.x);
}

TEST_F(CryptoTest, Ed25519CompressDecompress) {
    // Generate a valid Ed25519 point using hash_to_point
    Bytes uid = utils::string_to_bytes("test_user");
    Bytes did = utils::string_to_bytes("test_device");
    Bytes bid = utils::string_to_bytes("backup_001");
    Bytes pin = utils::string_to_bytes("1234");
    
    Point4D original = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    
    Bytes compressed = crypto::Ed25519::compress(original);
    EXPECT_EQ(compressed.size(), 32); // Ed25519 compressed points are 32 bytes
    
    // Test that decompression doesn't throw
    EXPECT_NO_THROW({
        Point4D decompressed = crypto::Ed25519::decompress(compressed);
        EXPECT_FALSE(decompressed.x.empty());
        EXPECT_FALSE(decompressed.y.empty());
        EXPECT_FALSE(decompressed.z.empty());
        EXPECT_FALSE(decompressed.t.empty());
    });
    
    // Test round-trip consistency: compress again and compare compressed data
    Point4D decompressed = crypto::Ed25519::decompress(compressed);
    Bytes compressed_again = crypto::Ed25519::compress(decompressed);
    EXPECT_EQ(compressed, compressed_again);
}

// Test Shamir Secret Sharing
TEST_F(CryptoTest, ShamirSecretSharing) {
    // Use a small secret that's definitely within the Ed25519 group order Q
    std::string secret = "deadbeefcafebabe1234567890abcdef";
    
    auto shares = crypto::ShamirSecretSharing::split_secret(secret, 3, 5);
    EXPECT_EQ(shares.size(), 5);
    
    // Test that we can recover the original secret
    std::vector<Share> recovery_shares = {shares[0], shares[2], shares[4]};
    std::string recovered = crypto::ShamirSecretSharing::recover_secret(recovery_shares);
    
    // Convert both to lowercase for comparison (hex can be case-insensitive)
    std::string secret_lower = secret;
    std::string recovered_lower = recovered;
    std::transform(secret_lower.begin(), secret_lower.end(), secret_lower.begin(), ::tolower);
    std::transform(recovered_lower.begin(), recovered_lower.end(), recovered_lower.begin(), ::tolower);
    
    EXPECT_EQ(secret_lower, recovered_lower);
    
    // Test with different share combination - should give same result
    std::vector<Share> recovery_shares_diff = {shares[1], shares[3], shares[4]};
    std::string recovered_diff = crypto::ShamirSecretSharing::recover_secret(recovery_shares_diff);
    std::string recovered_diff_lower = recovered_diff;
    std::transform(recovered_diff_lower.begin(), recovered_diff_lower.end(), recovered_diff_lower.begin(), ::tolower);
    
    EXPECT_EQ(secret_lower, recovered_diff_lower);
    
    // Both recovery attempts should give the same result
    EXPECT_EQ(recovered_lower, recovered_diff_lower);
}

TEST_F(CryptoTest, ShamirInsufficientShares) {
    std::string secret = "deadbeefcafebabe";
    int threshold = 3;
    int num_shares = 5;
    
    auto shares = crypto::ShamirSecretSharing::split_secret(secret, threshold, num_shares);
    
    // Try with insufficient shares
    std::vector<Share> insufficient_shares(shares.begin(), shares.begin() + threshold - 1);
    
    // This should either throw or return incorrect result
    // (depending on implementation - some implementations may not validate)
    std::string recovered = crypto::ShamirSecretSharing::recover_secret(insufficient_shares);
    EXPECT_NE(recovered, secret);
}

// Test key derivation from point
TEST_F(CryptoTest, DeriveEncryptionKey) {
    Point4D point("deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef",
                  "0123456789abcdef0123456789abcdefdeadbeefcafebabe1234567890abcdef",
                  "1", "0");
    
    Bytes key = crypto::derive_encryption_key(point);
    
    EXPECT_EQ(key.size(), 32); // SHA256 produces 32 bytes
    EXPECT_FALSE(key.empty());
    
    // Test deterministic behavior
    Bytes key2 = crypto::derive_encryption_key(point);
    EXPECT_EQ(key, key2);
}

// Test hex conversion utilities
TEST_F(CryptoTest, HexConversions) {
    Bytes data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::string hex = crypto::bytes_to_hex(data);
    EXPECT_EQ(hex, "deadbeef");
    
    Bytes converted_back = crypto::hex_to_bytes(hex);
    EXPECT_EQ(data, converted_back);
}

// Test AES-GCM with empty data
TEST_F(CryptoTest, AesGcmEmptyData) {
    Bytes key(32, 0x42);
    Bytes empty_data;
    
    auto result = crypto::aes_gcm_encrypt(empty_data, key);
    EXPECT_TRUE(result.ciphertext.empty());
    EXPECT_EQ(result.tag.size(), 16);
    EXPECT_EQ(result.nonce.size(), 12);
    
    // Decrypt empty data
    Bytes decrypted = crypto::aes_gcm_decrypt(result.ciphertext, result.tag, result.nonce, key);
    EXPECT_TRUE(decrypted.empty());
}

// Test AES-GCM with invalid key sizes
TEST_F(CryptoTest, AesGcmInvalidKeySize) {
    Bytes plaintext = utils::string_to_bytes("test");
    
    // Test with too short key
    Bytes short_key(16, 0x42); // 128-bit key
    EXPECT_NO_THROW(crypto::aes_gcm_encrypt(plaintext, short_key)); // Should work with 128-bit
    
    // Test with too long key  
    Bytes long_key(64, 0x42); // 512-bit key
    EXPECT_NO_THROW(crypto::aes_gcm_encrypt(plaintext, long_key)); // Should work, will be truncated
    
    // Test with empty key
    Bytes empty_key;
    EXPECT_THROW(crypto::aes_gcm_encrypt(plaintext, empty_key), OpenADPError);
}

// Test AES-GCM with invalid tag/nonce sizes
TEST_F(CryptoTest, AesGcmInvalidSizes) {
    Bytes key(32, 0x42);
    Bytes ciphertext = {1, 2, 3, 4};
    
    // Test with wrong tag size
    Bytes wrong_tag(8, 0x01); // Too short
    Bytes nonce(12, 0x02);
    EXPECT_THROW(crypto::aes_gcm_decrypt(ciphertext, wrong_tag, nonce, key), OpenADPError);
    
    // Test with wrong nonce size
    Bytes tag(16, 0x01);
    Bytes wrong_nonce(8, 0x02); // Too short
    EXPECT_THROW(crypto::aes_gcm_decrypt(ciphertext, tag, wrong_nonce, key), OpenADPError);
}

// Test HKDF with edge cases
TEST_F(CryptoTest, HkdfEdgeCases) {
    // Test with empty salt
    Bytes ikm = {1, 2, 3, 4};
    Bytes empty_salt;
    Bytes info = utils::string_to_bytes("test info");
    
    Bytes result = crypto::hkdf_derive(ikm, empty_salt, info, 32);
    EXPECT_EQ(result.size(), 32);
    
    // Test with empty info
    Bytes salt = {5, 6, 7, 8};
    Bytes empty_info;
    
    result = crypto::hkdf_derive(ikm, salt, empty_info, 32);
    EXPECT_EQ(result.size(), 32);
    
    // Test with zero length output
    EXPECT_THROW(crypto::hkdf_derive(ikm, salt, info, 0), OpenADPError);
    
    // Test with very large output length
    EXPECT_THROW(crypto::hkdf_derive(ikm, salt, info, 10000), OpenADPError);
}

// Test Shamir Secret Sharing edge cases
TEST_F(CryptoTest, ShamirEdgeCases) {
    std::string secret_hex = "01020304";
    
    // Test with threshold = 1
    auto shares = crypto::ShamirSecretSharing::split_secret(secret_hex, 1, 3);
    EXPECT_EQ(shares.size(), 3);
    
    // Recover with just one share
    std::vector<Share> single_share = {shares[0]};
    std::string recovered = crypto::ShamirSecretSharing::recover_secret(single_share);
    EXPECT_EQ(recovered, secret_hex);
    
    // Test with threshold = total shares
    shares = crypto::ShamirSecretSharing::split_secret(secret_hex, 3, 3);
    EXPECT_EQ(shares.size(), 3);
    
    // With insufficient shares, should give incorrect result (not throw)
    std::vector<Share> two_shares = {shares[0], shares[1]};
    std::string recovered_insufficient = crypto::ShamirSecretSharing::recover_secret(two_shares);
    // Convert both to lowercase for comparison
    std::string secret_lower = secret_hex;
    std::string recovered_lower = recovered_insufficient;
    std::transform(secret_lower.begin(), secret_lower.end(), secret_lower.begin(), ::tolower);
    std::transform(recovered_lower.begin(), recovered_lower.end(), recovered_lower.begin(), ::tolower);
    EXPECT_NE(secret_lower, recovered_lower); // Should be different with insufficient shares
    
    // Test with invalid parameters
    EXPECT_THROW(crypto::ShamirSecretSharing::split_secret(secret_hex, 2, 1), OpenADPError); // threshold > total
    EXPECT_THROW(crypto::ShamirSecretSharing::split_secret(secret_hex, 1, 0), OpenADPError); // total = 0
    EXPECT_THROW(crypto::ShamirSecretSharing::split_secret(secret_hex, 128, 256), OpenADPError); // total > 255
}

// Test Shamir with empty secret
TEST_F(CryptoTest, ShamirEmptySecret) {
    std::string empty_secret;
    
    EXPECT_THROW(crypto::ShamirSecretSharing::split_secret(empty_secret, 2, 3), OpenADPError);
}

// Test Shamir with duplicate share indices
TEST_F(CryptoTest, ShamirDuplicateIndices) {
    std::string secret_hex = "01020304";
    auto shares = crypto::ShamirSecretSharing::split_secret(secret_hex, 2, 3);
    
    // Create duplicate shares
    std::vector<Share> duplicate_shares = {shares[0], shares[0]};
    
    EXPECT_THROW(crypto::ShamirSecretSharing::recover_secret(duplicate_shares), OpenADPError);
}

// Test Shamir with corrupted share data
TEST_F(CryptoTest, ShamirCorruptedShares) {
    std::string secret_hex = "01020304";
    auto shares = crypto::ShamirSecretSharing::split_secret(secret_hex, 2, 3);
    
    // Corrupt one share by modifying its y value
    shares[0].y = "corrupted_value";
    
    std::vector<Share> corrupted_shares = {shares[0], shares[1]};
    std::string recovered = crypto::ShamirSecretSharing::recover_secret(corrupted_shares);
    
    // Should recover different data due to corruption
    EXPECT_NE(recovered, secret_hex);
}

// Test SHA256 with large data
TEST_F(CryptoTest, Sha256LargeData) {
    // Test with large input
    Bytes large_data(1000000, 0x42); // 1MB of data
    
    Bytes hash = crypto::sha256_hash(large_data);
    EXPECT_EQ(hash.size(), 32);
    
    // Hash should be deterministic
    Bytes hash2 = crypto::sha256_hash(large_data);
    EXPECT_EQ(hash, hash2);
}

// Test Ed25519 scalar multiplication
TEST_F(CryptoTest, Ed25519ScalarMult) {
    // Create a test point
    Bytes uid = utils::string_to_bytes("user");
    Bytes did = utils::string_to_bytes("device");
    Bytes bid = utils::string_to_bytes("backup");
    Bytes pin = utils::string_to_bytes("1234");
    
    Point4D point = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    
    // Test scalar multiplication
    std::string scalar_hex = "deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef";
    Point4D result = crypto::Ed25519::scalar_mult(scalar_hex, point);
    
    EXPECT_TRUE(crypto::Ed25519::is_valid_point(result));
}

// Test Ed25519 point operations
TEST_F(CryptoTest, Ed25519PointOperations) {
    // Create two test points
    Bytes uid1 = utils::string_to_bytes("user1");
    Bytes uid2 = utils::string_to_bytes("user2");
    Bytes did = utils::string_to_bytes("device");
    Bytes bid = utils::string_to_bytes("backup");
    Bytes pin = utils::string_to_bytes("1234");
    
    Point4D point1 = crypto::Ed25519::hash_to_point(uid1, did, bid, pin);
    Point4D point2 = crypto::Ed25519::hash_to_point(uid2, did, bid, pin);
    
    // Test point addition
    Point4D sum = crypto::Ed25519::point_add(point1, point2);
    EXPECT_TRUE(crypto::Ed25519::is_valid_point(sum));
    
    // Test point compression/decompression round-trip
    Bytes compressed = crypto::Ed25519::compress(point1);
    EXPECT_EQ(compressed.size(), 32);
    
    EXPECT_NO_THROW({
        Point4D decompressed = crypto::Ed25519::decompress(compressed);
        EXPECT_FALSE(decompressed.x.empty());
        EXPECT_FALSE(decompressed.y.empty());
        EXPECT_FALSE(decompressed.z.empty());
        EXPECT_FALSE(decompressed.t.empty());
        
        // Test that double compression gives same result
        Bytes compressed_again = crypto::Ed25519::compress(decompressed);
        EXPECT_EQ(compressed, compressed_again);
    });
    
    // Test expand/unexpand round-trip
    Point2D point2d = crypto::Ed25519::unexpand(point1);
    EXPECT_FALSE(point2d.x.empty());
    EXPECT_FALSE(point2d.y.empty());
    
    Point4D expanded = crypto::Ed25519::expand(point2d);
    EXPECT_FALSE(expanded.x.empty());
    EXPECT_FALSE(expanded.y.empty());
    EXPECT_FALSE(expanded.z.empty());
    EXPECT_FALSE(expanded.t.empty());
    
    // Test that unexpand/expand is consistent
    Point2D point2d_again = crypto::Ed25519::unexpand(expanded);
    EXPECT_EQ(point2d.x, point2d_again.x);
    EXPECT_EQ(point2d.y, point2d_again.y);
    
    // Test cofactor multiplication
    Point4D mul8 = crypto::Ed25519::point_mul8(point1);
    EXPECT_TRUE(crypto::Ed25519::is_valid_point(mul8));
}

// Test point secret sharing
TEST_F(CryptoTest, PointSecretSharing) {
    // Create a test point with coordinates within the Ed25519 group order Q
    Point2D point;
    point.x = "deadbeefcafebabe1234567890abcdef";
    point.y = "0123456789abcdefdeadbeefcafebabe";
    
    // Split point into shares
    auto shares = crypto::PointSecretSharing::split_point(point, 2, 3);
    EXPECT_EQ(shares.size(), 3);
    
    // Recover point from shares
    std::vector<PointShare> recovery_shares = {shares[0], shares[1]};
    Point2D recovered = crypto::PointSecretSharing::recover_point(recovery_shares);
    
    // Convert to lowercase for case-insensitive comparison
    std::string recovered_x_lower = recovered.x;
    std::string recovered_y_lower = recovered.y;
    std::string point_x_lower = point.x;
    std::string point_y_lower = point.y;
    
    std::transform(recovered_x_lower.begin(), recovered_x_lower.end(), recovered_x_lower.begin(), ::tolower);
    std::transform(recovered_y_lower.begin(), recovered_y_lower.end(), recovered_y_lower.begin(), ::tolower);
    std::transform(point_x_lower.begin(), point_x_lower.end(), point_x_lower.begin(), ::tolower);
    std::transform(point_y_lower.begin(), point_y_lower.end(), point_y_lower.begin(), ::tolower);
    
    EXPECT_EQ(recovered_x_lower, point_x_lower);
    EXPECT_EQ(recovered_y_lower, point_y_lower);
}

// Test key derivation
TEST_F(CryptoTest, KeyDerivation) {
    // Create a test point
    Bytes uid = utils::string_to_bytes("user");
    Bytes did = utils::string_to_bytes("device");
    Bytes bid = utils::string_to_bytes("backup");
    Bytes pin = utils::string_to_bytes("1234");
    
    Point4D point = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    
    // Derive encryption key
    Bytes key = crypto::derive_encryption_key(point);
    EXPECT_EQ(key.size(), 32);
    
    // Should be deterministic
    Bytes key2 = crypto::derive_encryption_key(point);
    EXPECT_EQ(key, key2);
}

// Test utility functions
TEST_F(CryptoTest, UtilityFunctions) {
    Bytes test_data = {0x01, 0x02, 0x03, 0x04};
    
    // Test hex conversion
    std::string hex = crypto::bytes_to_hex(test_data);
    EXPECT_EQ(hex, "01020304");
    
    Bytes converted_back = crypto::hex_to_bytes(hex);
    EXPECT_EQ(converted_back, test_data);
    
    // Test prefixed function
    Bytes prefixed_data = crypto::prefixed(test_data);
    EXPECT_GT(prefixed_data.size(), test_data.size());
}

// Test crypto operations with maximum size inputs
TEST_F(CryptoTest, MaximumSizeInputs) {
    // Test AES-GCM with large plaintext
    Bytes large_plaintext(100000, 0x42); // 100KB
    Bytes key(32, 0x01);
    
    auto result = crypto::aes_gcm_encrypt(large_plaintext, key);
    EXPECT_EQ(result.ciphertext.size(), large_plaintext.size());
    
    Bytes decrypted = crypto::aes_gcm_decrypt(result.ciphertext, result.tag, result.nonce, key);
    EXPECT_EQ(decrypted, large_plaintext);
}

} // namespace test
} // namespace openadp 