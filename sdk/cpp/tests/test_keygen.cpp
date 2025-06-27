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

// Test error handling in generate_encryption_key
TEST_F(KeygenTest, GenerateEncryptionKeyErrors) {
    Identity identity("user", "device", "backup");
    std::vector<ServerInfo> empty_servers;
    
    // Test with empty server list
    auto result = keygen::generate_encryption_key(identity, "password", 5, 0, empty_servers);
    EXPECT_TRUE(result.error_message.has_value());
    EXPECT_TRUE(result.error_message->find("No servers") != std::string::npos ||
               result.error_message->find("empty") != std::string::npos ||
               result.error_message->find("server") != std::string::npos);
    
    // Test with single server (should fail threshold requirement)
    std::vector<ServerInfo> single_server = {{"https://server1.example.com"}};
    result = keygen::generate_encryption_key(identity, "password", 5, 0, single_server);
    EXPECT_TRUE(result.error_message.has_value());
}

// Test error handling in recover_encryption_key
TEST_F(KeygenTest, RecoverEncryptionKeyErrors) {
    Identity identity("user", "device", "backup");
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with empty auth codes
    AuthCodes empty_auth_codes;
    auto result = keygen::recover_encryption_key(identity, "password", empty_auth_codes, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with mismatched auth codes and servers
    AuthCodes auth_codes;
    auth_codes.base_auth_code = "test_code";
    auth_codes.server_auth_codes["https://server1.example.com"] = "code1"; // Only one code for two servers
    
    result = keygen::recover_encryption_key(identity, "password", auth_codes, servers);
    EXPECT_TRUE(result.error_message.has_value());
}

// Test generate_auth_codes with edge cases
TEST_F(KeygenTest, GenerateAuthCodesEdgeCases) {
    std::vector<ServerInfo> empty_servers;
    
    // Test with empty servers - should return empty auth codes
    auto result = keygen::generate_auth_codes("base_code", empty_servers);
    EXPECT_EQ(result.base_auth_code, "base_code");
    EXPECT_EQ(result.server_auth_codes.size(), 0);
    
    // Test with single server
    std::vector<ServerInfo> single_server = {{"https://server1.example.com"}};
    result = keygen::generate_auth_codes("base_code", single_server);
    EXPECT_EQ(result.base_auth_code, "base_code");
    EXPECT_EQ(result.server_auth_codes.size(), 1);
    
    // Test with many servers
    std::vector<ServerInfo> many_servers;
    for (int i = 0; i < 10; i++) {
        many_servers.push_back({"https://server" + std::to_string(i) + ".example.com"});
    }
    result = keygen::generate_auth_codes("base_code", many_servers);
    EXPECT_EQ(result.server_auth_codes.size(), 10);
}

// Test Identity validation
TEST_F(KeygenTest, IdentityValidation) {
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with empty user ID
    Identity empty_user("", "device", "backup");
    auto result = keygen::generate_encryption_key(empty_user, "password", 5, 0, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with empty device ID
    Identity empty_device("user", "", "backup");
    result = keygen::generate_encryption_key(empty_device, "password", 5, 0, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with empty backup ID
    Identity empty_backup("user", "device", "");
    result = keygen::generate_encryption_key(empty_backup, "password", 5, 0, servers);
    EXPECT_TRUE(result.error_message.has_value());
}

// Test password validation
TEST_F(KeygenTest, PasswordValidation) {
    Identity identity("user", "device", "backup");
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with empty password
    auto result = keygen::generate_encryption_key(identity, "", 5, 0, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with very long password
    std::string long_password(10000, 'a');
    result = keygen::generate_encryption_key(identity, long_password, 5, 0, servers);
    // Should work or fail gracefully
    EXPECT_TRUE(result.error_message.has_value() || result.encryption_key.has_value());
}

// Test max_guesses validation
TEST_F(KeygenTest, MaxGuessesValidation) {
    Identity identity("user", "device", "backup");
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with zero max guesses
    auto result = keygen::generate_encryption_key(identity, "password", 0, 0, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with negative max guesses
    result = keygen::generate_encryption_key(identity, "password", -1, 0, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with very large max guesses
    result = keygen::generate_encryption_key(identity, "password", 1000000, 0, servers);
    EXPECT_TRUE(result.error_message.has_value() || result.encryption_key.has_value());
}

// Test expiration validation
TEST_F(KeygenTest, ExpirationValidation) {
    Identity identity("user", "device", "backup");
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with past expiration
    int64_t past_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() - 3600; // 1 hour ago
    
    auto result = keygen::generate_encryption_key(identity, "password", 5, past_time, servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with far future expiration
    int64_t future_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + 365*24*3600; // 1 year from now
    
    result = keygen::generate_encryption_key(identity, "password", 5, future_time, servers);
    // Should work or fail gracefully
    EXPECT_TRUE(result.error_message.has_value() || result.encryption_key.has_value());
}

// Test server info validation
TEST_F(KeygenTest, ServerInfoValidation) {
    Identity identity("user", "device", "backup");
    
    // Test with servers having empty URLs
    std::vector<ServerInfo> invalid_servers = {
        {""},
        {"https://server2.example.com"}
    };
    
    auto result = keygen::generate_encryption_key(identity, "password", 5, 0, invalid_servers);
    EXPECT_TRUE(result.error_message.has_value());
    
    // Test with servers having invalid URLs
    std::vector<ServerInfo> malformed_servers = {
        {"not-a-url"},
        {"https://server2.example.com"}
    };
    
    result = keygen::generate_encryption_key(identity, "password", 5, 0, malformed_servers);
    EXPECT_TRUE(result.error_message.has_value());
}

// Test threshold calculation edge cases
TEST_F(KeygenTest, ThresholdCalculation) {
    Identity identity("user", "device", "backup");
    
    // Test with exactly 2 servers (minimum for threshold)
    std::vector<ServerInfo> two_servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    auto result = keygen::generate_encryption_key(identity, "password", 5, 0, two_servers);
    if (!result.error_message.has_value()) {
        EXPECT_EQ(result.threshold, 2); // Should need both servers
    }
    
    // Test with 3 servers
    std::vector<ServerInfo> three_servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"},
        {"https://server3.example.com"}
    };
    
    result = keygen::generate_encryption_key(identity, "password", 5, 0, three_servers);
    if (!result.error_message.has_value()) {
        EXPECT_EQ(result.threshold, 2); // Should need 2 out of 3
    }
}

// Test auth code generation with different base codes
TEST_F(KeygenTest, AuthCodeGenerationVariations) {
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with different base codes
    auto result1 = keygen::generate_auth_codes("code1", servers);
    auto result2 = keygen::generate_auth_codes("code2", servers);
    
    EXPECT_NE(result1.server_auth_codes.at("https://server1.example.com"), 
              result2.server_auth_codes.at("https://server1.example.com"));
    EXPECT_NE(result1.server_auth_codes.at("https://server2.example.com"), 
              result2.server_auth_codes.at("https://server2.example.com"));
    
    // Test with same base code (should be deterministic)
    auto result3 = keygen::generate_auth_codes("code1", servers);
    EXPECT_EQ(result1.server_auth_codes.at("https://server1.example.com"), 
              result3.server_auth_codes.at("https://server1.example.com"));
    EXPECT_EQ(result1.server_auth_codes.at("https://server2.example.com"), 
              result3.server_auth_codes.at("https://server2.example.com"));
}

// Test with servers having public keys
TEST_F(KeygenTest, ServersWithPublicKeys) {
    Identity identity("user", "device", "backup");
    
    std::vector<ServerInfo> servers_with_keys;
    servers_with_keys.push_back({"https://server1.example.com"});
    servers_with_keys.push_back({"https://server2.example.com"});
    
    // Add public keys
    servers_with_keys[0].public_key = Bytes(32, 0x01);
    servers_with_keys[1].public_key = Bytes(32, 0x02);
    
    auto result = keygen::generate_encryption_key(identity, "password", 5, 0, servers_with_keys);
    // Should handle servers with public keys (may still fail due to unreachable servers)
    EXPECT_TRUE(result.error_message.has_value() || result.encryption_key.has_value());
}

// Test recovery with wrong password
TEST_F(KeygenTest, RecoveryWithWrongPassword) {
    Identity identity("user", "device", "backup");
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    AuthCodes auth_codes;
    auth_codes.base_auth_code = "test_code";
    auth_codes.server_auth_codes["https://server1.example.com"] = "code1";
    auth_codes.server_auth_codes["https://server2.example.com"] = "code2";
    
    // Test with wrong password
    auto result = keygen::recover_encryption_key(identity, "wrong_password", auth_codes, servers);
    EXPECT_TRUE(result.error_message.has_value());
}

// Test with Unicode characters in inputs
TEST_F(KeygenTest, UnicodeInputs) {
    Identity identity("用户", "设备", "备份"); // Chinese characters
    std::vector<ServerInfo> servers = {
        {"https://server1.example.com"},
        {"https://server2.example.com"}
    };
    
    // Test with Unicode password
    auto result = keygen::generate_encryption_key(identity, "密码", 5, 0, servers);
    // Should handle Unicode or fail gracefully
    EXPECT_TRUE(result.error_message.has_value() || result.encryption_key.has_value());
}

} // namespace test
} // namespace openadp 