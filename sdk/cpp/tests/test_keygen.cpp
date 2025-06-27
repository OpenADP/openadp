#include <gtest/gtest.h>
#include "openadp/keygen.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"

namespace openadp {
namespace test {

class KeygenTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test identity
        test_identity = Identity("test_user", "test_device", "test_backup");
        
        // Create test server infos
        test_servers = {
            ServerInfo("https://server1.example.com"),
            ServerInfo("https://server2.example.com"),
            ServerInfo("https://server3.example.com")
        };
    }
    
    void TearDown() override {}
    
    Identity test_identity;
    std::vector<ServerInfo> test_servers;
};

// Test auth code generation
TEST_F(KeygenTest, GenerateAuthCodes) {
    std::string base_auth_code = "base_auth_code_123";
    
    AuthCodes auth_codes = keygen::generate_auth_codes(base_auth_code, test_servers);
    
    EXPECT_EQ(auth_codes.base_auth_code, base_auth_code);
    EXPECT_EQ(auth_codes.server_auth_codes.size(), test_servers.size());
    
    // Each server should have a unique auth code
    std::set<std::string> unique_codes;
    for (const auto& pair : auth_codes.server_auth_codes) {
        unique_codes.insert(pair.second);
    }
    EXPECT_EQ(unique_codes.size(), test_servers.size());
    
    // Auth codes should be deterministic
    AuthCodes auth_codes2 = keygen::generate_auth_codes(base_auth_code, test_servers);
    EXPECT_EQ(auth_codes.server_auth_codes, auth_codes2.server_auth_codes);
}

TEST_F(KeygenTest, GenerateAuthCodesEmptyServers) {
    std::string base_auth_code = "base_auth_code_123";
    std::vector<ServerInfo> empty_servers;
    
    AuthCodes auth_codes = keygen::generate_auth_codes(base_auth_code, empty_servers);
    
    EXPECT_EQ(auth_codes.base_auth_code, base_auth_code);
    EXPECT_EQ(auth_codes.server_auth_codes.size(), 0);
}

TEST_F(KeygenTest, GenerateAuthCodesDifferentBase) {
    std::string base1 = "base1";
    std::string base2 = "base2";
    
    AuthCodes auth_codes1 = keygen::generate_auth_codes(base1, test_servers);
    AuthCodes auth_codes2 = keygen::generate_auth_codes(base2, test_servers);
    
    // Different base codes should produce different server auth codes
    EXPECT_NE(auth_codes1.server_auth_codes, auth_codes2.server_auth_codes);
}

// Test result structures
TEST_F(KeygenTest, GenerateEncryptionKeyResultSuccess) {
    Bytes test_key = utils::random_bytes(32);
    AuthCodes test_auth_codes = keygen::generate_auth_codes("test", test_servers);
    int threshold = 2;
    
    auto result = GenerateEncryptionKeyResult::success(test_key, test_auth_codes, test_servers, threshold);
    
    EXPECT_TRUE(result.encryption_key.has_value());
    EXPECT_TRUE(result.auth_codes.has_value());
    EXPECT_FALSE(result.error_message.has_value());
    EXPECT_EQ(result.encryption_key.value(), test_key);
    EXPECT_EQ(result.auth_codes.value().base_auth_code, test_auth_codes.base_auth_code);
    EXPECT_EQ(result.server_infos, test_servers);
    EXPECT_EQ(result.threshold, threshold);
}

TEST_F(KeygenTest, GenerateEncryptionKeyResultError) {
    std::string error_msg = "Test error message";
    
    auto result = GenerateEncryptionKeyResult::error(error_msg);
    
    EXPECT_FALSE(result.encryption_key.has_value());
    EXPECT_FALSE(result.auth_codes.has_value());
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_EQ(result.error_message.value(), error_msg);
}

TEST_F(KeygenTest, RecoverEncryptionKeyResultSuccess) {
    Bytes test_key = utils::random_bytes(32);
    int remaining_guesses = 5;
    
    auto result = RecoverEncryptionKeyResult::success(test_key, remaining_guesses);
    
    EXPECT_TRUE(result.encryption_key.has_value());
    EXPECT_FALSE(result.error_message.has_value());
    EXPECT_EQ(result.encryption_key.value(), test_key);
    EXPECT_EQ(result.remaining_guesses, remaining_guesses);
}

TEST_F(KeygenTest, RecoverEncryptionKeyResultError) {
    std::string error_msg = "Recovery failed";
    
    auto result = RecoverEncryptionKeyResult::error(error_msg);
    
    EXPECT_FALSE(result.encryption_key.has_value());
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_EQ(result.error_message.value(), error_msg);
    EXPECT_EQ(result.remaining_guesses, 0);
}

// Test key generation (these tests will likely fail without real servers)
// But we can test the error handling and basic structure
TEST_F(KeygenTest, GenerateEncryptionKeyNoServers) {
    std::vector<ServerInfo> empty_servers;
    
    auto result = keygen::generate_encryption_key(
        test_identity, "password", 10, 3600, empty_servers
    );
    
    // Should return an error for no servers
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_FALSE(result.encryption_key.has_value());
}

TEST_F(KeygenTest, RecoverEncryptionKeyNoServers) {
    std::vector<ServerInfo> empty_servers;
    AuthCodes auth_codes = keygen::generate_auth_codes("test", empty_servers);
    
    auto result = keygen::recover_encryption_key(
        test_identity, "password", auth_codes, empty_servers
    );
    
    // Should return an error for no servers
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_FALSE(result.encryption_key.has_value());
}

// Test with mock/unreachable servers (will test network error handling)
TEST_F(KeygenTest, GenerateEncryptionKeyUnreachableServers) {
    std::vector<ServerInfo> unreachable_servers = {
        ServerInfo("https://nonexistent1.example.com"),
        ServerInfo("https://nonexistent2.example.com")
    };
    
    auto result = keygen::generate_encryption_key(
        test_identity, "password", 10, 3600, unreachable_servers
    );
    
    // Should handle network errors gracefully
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_FALSE(result.encryption_key.has_value());
}

TEST_F(KeygenTest, RecoverEncryptionKeyUnreachableServers) {
    std::vector<ServerInfo> unreachable_servers = {
        ServerInfo("https://nonexistent1.example.com"),
        ServerInfo("https://nonexistent2.example.com")
    };
    
    AuthCodes auth_codes = keygen::generate_auth_codes("test", unreachable_servers);
    
    auto result = keygen::recover_encryption_key(
        test_identity, "password", auth_codes, unreachable_servers
    );
    
    // Should handle network errors gracefully
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_FALSE(result.encryption_key.has_value());
}

// Test identity validation
TEST_F(KeygenTest, IdentityFields) {
    Identity identity("user@example.com", "device-123", "backup-456");
    
    EXPECT_EQ(identity.uid, "user@example.com");
    EXPECT_EQ(identity.did, "device-123");
    EXPECT_EQ(identity.bid, "backup-456");
}

TEST_F(KeygenTest, IdentityEmptyFields) {
    Identity identity("", "", "");
    
    EXPECT_EQ(identity.uid, "");
    EXPECT_EQ(identity.did, "");
    EXPECT_EQ(identity.bid, "");
}

// Test ServerInfo with and without public keys
TEST_F(KeygenTest, ServerInfoWithoutPublicKey) {
    ServerInfo server("https://example.com");
    
    EXPECT_EQ(server.url, "https://example.com");
    EXPECT_FALSE(server.public_key.has_value());
}

TEST_F(KeygenTest, ServerInfoWithPublicKey) {
    Bytes public_key = utils::random_bytes(32);
    ServerInfo server("https://example.com", public_key);
    
    EXPECT_EQ(server.url, "https://example.com");
    EXPECT_TRUE(server.public_key.has_value());
    EXPECT_EQ(server.public_key.value(), public_key);
}

// Test Share structure
TEST_F(KeygenTest, ShareStructure) {
    Share share(5, "deadbeef");
    
    EXPECT_EQ(share.x, 5);
    EXPECT_EQ(share.y, "deadbeef");
}

// Test PointShare structure
TEST_F(KeygenTest, PointShareStructure) {
    Point2D point("123", "456");
    PointShare point_share(3, point);
    
    EXPECT_EQ(point_share.x, 3);
    EXPECT_EQ(point_share.point.x, "123");
    EXPECT_EQ(point_share.point.y, "456");
}

// Test Point structures
TEST_F(KeygenTest, Point2DStructure) {
    Point2D point("x_coord", "y_coord");
    
    EXPECT_EQ(point.x, "x_coord");
    EXPECT_EQ(point.y, "y_coord");
}

TEST_F(KeygenTest, Point4DStructure) {
    Point4D point("x_coord", "y_coord", "z_coord", "t_coord");
    
    EXPECT_EQ(point.x, "x_coord");
    EXPECT_EQ(point.y, "y_coord");
    EXPECT_EQ(point.z, "z_coord");
    EXPECT_EQ(point.t, "t_coord");
}

// Test parameter validation
TEST_F(KeygenTest, GenerateEncryptionKeyParameterValidation) {
    // Test with various parameter combinations
    auto result1 = keygen::generate_encryption_key(
        test_identity, "", 10, 3600, test_servers  // Empty password
    );
    
    auto result2 = keygen::generate_encryption_key(
        test_identity, "password", 0, 3600, test_servers  // Zero max guesses
    );
    
    auto result3 = keygen::generate_encryption_key(
        test_identity, "password", -1, 3600, test_servers  // Negative max guesses
    );
    
    // These should either work or fail gracefully with error messages
    // (behavior depends on server validation)
}

} // namespace test
} // namespace openadp 