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
    Bytes uid = utils::string_to_bytes("user123");
    Bytes did = utils::string_to_bytes("device456");
    Bytes bid = utils::string_to_bytes("backup789");
    Bytes pin = utils::string_to_bytes("1234");
    
    Point4D point = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    
    EXPECT_FALSE(point.x.empty());
    EXPECT_FALSE(point.y.empty());
    EXPECT_FALSE(point.z.empty());
    EXPECT_FALSE(point.t.empty());
    
    // Test deterministic behavior
    Point4D point2 = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    EXPECT_EQ(point.x, point2.x);
    EXPECT_EQ(point.y, point2.y);
    EXPECT_EQ(point.z, point2.z);
    EXPECT_EQ(point.t, point2.t);
}

TEST_F(CryptoTest, Ed25519CompressDecompress) {
    Point4D original("01D3FA31B7A6844F7B24DED7F6608D9BDC2B00446A1EEE62CDBAD4B276EB4AF9",
                     "01D3FA31B7A6844F7B24DED7F6608D9BDC2B00446A1EEE62CDBAD4B276EB4AF9",
                     "1", "0");
    
    Bytes compressed = crypto::Ed25519::compress(original);
    Point4D decompressed = crypto::Ed25519::decompress(compressed);
    
    // Convert to lowercase for comparison (hex can be case-insensitive)
    std::string original_y_lower = original.y;
    std::string decompressed_y_lower = decompressed.y;
    std::transform(original_y_lower.begin(), original_y_lower.end(), original_y_lower.begin(), ::tolower);
    std::transform(decompressed_y_lower.begin(), decompressed_y_lower.end(), decompressed_y_lower.begin(), ::tolower);
    
    EXPECT_EQ(original_y_lower, decompressed_y_lower);
}

// Test Shamir Secret Sharing
TEST_F(CryptoTest, ShamirSecretSharing) {
    // Use a simple secret for testing
    std::string secret = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    
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

} // namespace test
} // namespace openadp 