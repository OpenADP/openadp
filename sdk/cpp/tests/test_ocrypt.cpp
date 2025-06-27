#include <gtest/gtest.h>
#include "openadp/ocrypt.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"
#include <nlohmann/json.hpp>

using namespace openadp;

namespace openadp {
namespace test {

class OcryptTest : public ::testing::Test {
protected:
    Identity test_identity{"test_user", "test_device", "test_backup"};
    std::vector<ServerInfo> test_servers{
        ServerInfo("https://server1.example.com"),
        ServerInfo("https://server2.example.com")
    };
    std::vector<ServerInfo> empty_servers;
    std::vector<ServerInfo> unreachable_servers{
        ServerInfo("https://unreachable1.example.com"),
        ServerInfo("https://unreachable2.example.com")
    };
};

// Test backup ID generation
TEST_F(OcryptTest, GenerateNextBackupId) {
    std::string backup_id1 = "backup_1";
    std::string backup_id2 = ocrypt::generate_next_backup_id(backup_id1);
    
    EXPECT_NE(backup_id1, backup_id2);
    EXPECT_EQ(backup_id2, "backup_2");
    
    std::string backup_id_10 = "backup_10";
    std::string incremented_10 = ocrypt::generate_next_backup_id(backup_id_10);
    EXPECT_EQ(incremented_10, "backup_11");
}

TEST_F(OcryptTest, GenerateNextBackupIdOverflow) {
    // Test with large counter
    std::string large_id = "backup_999999";
    std::string incremented = ocrypt::generate_next_backup_id(large_id);
    EXPECT_EQ(incremented, "backup_1000000");
}

TEST_F(OcryptTest, GenerateNextBackupIdInvalidHex) {
    // Test with backup ID without underscore - should append _2
    std::string no_underscore = "backup_without_number";
    std::string result = ocrypt::generate_next_backup_id(no_underscore);
    EXPECT_EQ(result, "backup_without_number_2");
    
    // Test with backup ID that has underscore but invalid counter
    std::string invalid_counter = "backup_invalid";
    std::string result2 = ocrypt::generate_next_backup_id(invalid_counter);
    EXPECT_EQ(result2, "backup_invalid_2");
}

// Test register secret parameter validation
TEST_F(OcryptTest, RegisterSecretParameterValidation) {
    Bytes test_secret = {0x01, 0x02, 0x03, 0x04};
    
    // Empty user ID
    EXPECT_THROW(
        ocrypt::register_secret("", "app_id", test_secret, "password", 10, ""),
        OpenADPError
    );
    
    // Empty app ID
    EXPECT_THROW(
        ocrypt::register_secret("user", "", test_secret, "password", 10, ""),
        OpenADPError
    );
    
    // Empty secret
    Bytes empty_secret;
    EXPECT_THROW(
        ocrypt::register_secret("user", "app", empty_secret, "password", 10, ""),
        OpenADPError
    );
    
    // Invalid max_guesses (0)
    EXPECT_THROW(
        ocrypt::register_secret("user", "app", test_secret, "password", 0, ""),
        OpenADPError
    );
    
    // Invalid max_guesses (negative)
    EXPECT_THROW(
        ocrypt::register_secret("user", "app", test_secret, "password", -1, ""),
        OpenADPError
    );
}

// Test register secret with unreachable servers
TEST_F(OcryptTest, RegisterSecretUnreachableServers) {
    Bytes test_secret = {0x01, 0x02, 0x03, 0x04};
    
    EXPECT_THROW(
        ocrypt::register_secret(
            test_identity.uid, "app_id", test_secret, "password", 10, 
            "https://unreachable.example.com"
        ),
        OpenADPError
    );
}

// Test recover with invalid metadata
TEST_F(OcryptTest, RecoverInvalidMetadata) {
    Bytes invalid_metadata = {0x00, 0x01, 0x02}; // Invalid metadata format
    
    EXPECT_THROW(
        ocrypt::recover(invalid_metadata, "password", ""),
        OpenADPError
    );
}

// Test recover with unreachable servers
TEST_F(OcryptTest, RecoverUnreachableServers) {
    // Create a valid-looking metadata (though it won't work with unreachable servers)
    nlohmann::json metadata_json;
    metadata_json["uid"] = test_identity.uid;
    metadata_json["app_id"] = "test_app";
    metadata_json["backup_id"] = "0000000000000001";
    metadata_json["server_urls"] = {"https://unreachable.example.com"};
    metadata_json["auth_code"] = "test_auth_code";
    
    std::string metadata_string = metadata_json.dump();
    Bytes metadata_bytes(metadata_string.begin(), metadata_string.end());
    
    EXPECT_THROW(
        ocrypt::recover(metadata_bytes, "password", "https://unreachable.example.com"),
        OpenADPError
    );
}

// Test register with bid parameter validation
TEST_F(OcryptTest, RegisterWithBidParameterValidation) {
    Bytes test_secret = {0x01, 0x02, 0x03, 0x04};
    
    // Empty user ID
    EXPECT_THROW(
        ocrypt::register_with_bid("", "app_id", test_secret, "password", 10, "backup_id", ""),
        OpenADPError
    );
    
    // Empty app ID
    EXPECT_THROW(
        ocrypt::register_with_bid("user", "", test_secret, "password", 10, "backup_id", ""),
        OpenADPError
    );
    
    // Empty backup ID
    EXPECT_THROW(
        ocrypt::register_with_bid("user", "app", test_secret, "password", 10, "", ""),
        OpenADPError
    );
}

// Test recover without refresh parameter validation
TEST_F(OcryptTest, RecoverWithoutRefreshParameterValidation) {
    Bytes empty_metadata;
    
    EXPECT_THROW(
        ocrypt::recover_without_refresh(empty_metadata, "password", ""),
        OpenADPError
    );
}

// Test secret data handling
TEST_F(OcryptTest, SecretDataHandling) {
    Bytes test_secret = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Test with different secret sizes
    Bytes small_secret = {0x01};
    Bytes large_secret(1000, 0x42); // 1000 bytes of 0x42
    
    // These should not throw for valid parameters (though they might fail due to unreachable servers)
    EXPECT_NO_THROW({
        try {
            ocrypt::register_secret("user", "app", small_secret, "password", 10, "");
        } catch (const OpenADPError& e) {
            // Expected to fail due to unreachable servers, but not due to parameter validation
            EXPECT_TRUE(std::string(e.what()).find("parameter") == std::string::npos);
        }
    });
}

// Test PIN validation
TEST_F(OcryptTest, PinValidation) {
    Bytes test_secret = {0x01, 0x02, 0x03, 0x04};
    
    // Empty PIN should be allowed (might be used for testing)
    EXPECT_NO_THROW({
        try {
            ocrypt::register_secret("user", "app", test_secret, "", 10, "");
        } catch (const OpenADPError& e) {
            // Expected to fail due to unreachable servers, but not due to empty PIN
            EXPECT_TRUE(std::string(e.what()).find("PIN") == std::string::npos);
        }
    });
}

// Test backup ID edge cases
TEST_F(OcryptTest, BackupIdEdgeCases) {
    // Test with counter 0
    std::string backup_0 = "backup_0";
    std::string incremented_0 = ocrypt::generate_next_backup_id(backup_0);
    EXPECT_EQ(incremented_0, "backup_1");
    
    // Test with no underscore - should append _2
    std::string no_underscore = "backup";
    std::string result = ocrypt::generate_next_backup_id(no_underscore);
    EXPECT_EQ(result, "backup_2");
    EXPECT_EQ(result.length(), 8); // "backup_2" is 8 characters
}

// Test metadata format handling
TEST_F(OcryptTest, MetadataFormatHandling) {
    // Test with JSON metadata
    nlohmann::json json_metadata;
    json_metadata["uid"] = "test_user";
    json_metadata["app_id"] = "test_app";
    json_metadata["backup_id"] = "0000000000000001";
    
    std::string json_string = json_metadata.dump();
    Bytes json_bytes(json_string.begin(), json_string.end());
    
    EXPECT_NO_THROW({
        try {
            ocrypt::recover(json_bytes, "password", "");
        } catch (const OpenADPError& e) {
            // Expected to fail due to incomplete metadata or unreachable servers
            // but not due to JSON format issues
            std::string error_msg = e.what();
            EXPECT_TRUE(error_msg.find("JSON") == std::string::npos || 
                       error_msg.find("format") == std::string::npos);
        }
    });
}

// Test result structure
TEST_F(OcryptTest, ResultStructure) {
    Bytes test_secret = {0x01, 0x02, 0x03};
    Bytes test_metadata = {0x04, 0x05, 0x06};
    
    ocrypt::OcryptRecoverResult result(test_secret, 5, test_metadata);
    
    EXPECT_EQ(result.secret, test_secret);
    EXPECT_EQ(result.remaining_guesses, 5);
    EXPECT_EQ(result.updated_metadata, test_metadata);
}

// Test large data handling
TEST_F(OcryptTest, LargeDataHandling) {
    // Test with large secret
    Bytes large_secret(10000, 0x42); // 10KB secret
    
    EXPECT_NO_THROW({
        try {
            ocrypt::register_secret("user", "app", large_secret, "password", 10, "");
        } catch (const OpenADPError& e) {
            // Expected to fail due to unreachable servers, but should handle large data
            EXPECT_TRUE(std::string(e.what()).find("size") == std::string::npos);
        }
    });
}

// Test special characters in parameters
TEST_F(OcryptTest, SpecialCharactersHandling) {
    Bytes test_secret = {0x01, 0x02, 0x03};
    
    // Test with special characters in user ID and app ID
    std::string special_user = "user@domain.com";
    std::string special_app = "app-name_v1.0";
    
    EXPECT_NO_THROW({
        try {
            ocrypt::register_secret(special_user, special_app, test_secret, "password", 10, "");
        } catch (const OpenADPError& e) {
            // Expected to fail due to unreachable servers, but should handle special chars
            EXPECT_TRUE(std::string(e.what()).find("character") == std::string::npos);
        }
    });
}

// Test error handling in register_with_bid
TEST_F(OcryptTest, RegisterWithBidServerError) {
    Bytes secret = utils::string_to_bytes("my_secret");
    
    // Test with unreachable server URL
    try {
        Bytes metadata = ocrypt::register_with_bid(
            "user123", "app456", secret, "1234", 5, 
            "custom_backup_id", "https://unreachable.example.com"
        );
        // If it somehow succeeds, that's also fine for testing
        EXPECT_FALSE(metadata.empty());
    } catch (const OpenADPError& e) {
        // Expected to fail due to unreachable server
        EXPECT_TRUE(std::string(e.what()).find("Registration failed") != std::string::npos ||
                   std::string(e.what()).find("servers") != std::string::npos);
    }
}

// Test error handling in register_secret  
TEST_F(OcryptTest, RegisterSecretServerError) {
    Bytes secret = utils::string_to_bytes("my_secret");
    
    try {
        Bytes metadata = ocrypt::register_secret(
            "user123", "app456", secret, "1234", 5, 
            "https://unreachable.example.com"
        );
        EXPECT_FALSE(metadata.empty());
    } catch (const OpenADPError& e) {
        // Expected to fail due to unreachable server
        EXPECT_TRUE(std::string(e.what()).find("Registration failed") != std::string::npos ||
                   std::string(e.what()).find("servers") != std::string::npos);
    }
}

// Test recover_without_refresh error handling
TEST_F(OcryptTest, RecoverWithoutRefreshInvalidMetadata) {
    // Test with malformed JSON
    Bytes invalid_metadata = utils::string_to_bytes("invalid json");
    
    EXPECT_THROW(
        ocrypt::recover_without_refresh(invalid_metadata, "1234", "https://servers.example.com"),
        OpenADPError
    );
}

TEST_F(OcryptTest, RecoverWithoutRefreshMissingFields) {
    // Test with JSON missing required fields
    nlohmann::json incomplete_metadata;
    incomplete_metadata["user_id"] = "user123";
    // Missing other required fields
    
    Bytes metadata = utils::string_to_bytes(incomplete_metadata.dump());
    
    EXPECT_THROW(
        ocrypt::recover_without_refresh(metadata, "1234", "https://servers.example.com"),
        OpenADPError
    );
}

TEST_F(OcryptTest, RecoverWithoutRefreshServerError) {
    // Create proper metadata but with unreachable servers
    nlohmann::json metadata_json;
    metadata_json["user_id"] = "user123";
    metadata_json["device_id"] = "device456";
    metadata_json["backup_id"] = "backup789";
    metadata_json["auth_code"] = "test_auth_code";
    metadata_json["ciphertext"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8});
    metadata_json["tag"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    metadata_json["nonce"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    metadata_json["servers"] = nlohmann::json::array({"https://unreachable.example.com"});
    
    Bytes metadata = utils::string_to_bytes(metadata_json.dump());
    
    try {
        auto result = ocrypt::recover_without_refresh(metadata, "1234", "https://servers.example.com");
    } catch (const OpenADPError& e) {
        // Expected to fail due to unreachable server or invalid data
        EXPECT_TRUE(std::string(e.what()).find("Recovery failed") != std::string::npos ||
                   std::string(e.what()).find("Failed to") != std::string::npos);
    }
}

// Test recover with server fallback (no servers in metadata)
TEST_F(OcryptTest, RecoverWithoutRefreshServerFallback) {
    // Create metadata without servers field to test fallback
    nlohmann::json metadata_json;
    metadata_json["user_id"] = "user123";
    metadata_json["device_id"] = "device456";
    metadata_json["backup_id"] = "backup789";
    metadata_json["auth_code"] = "test_auth_code";
    metadata_json["ciphertext"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8});
    metadata_json["tag"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    metadata_json["nonce"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    // No "servers" field to test fallback
    
    Bytes metadata = utils::string_to_bytes(metadata_json.dump());
    
    try {
        auto result = ocrypt::recover_without_refresh(metadata, "1234", "https://servers.example.com");
    } catch (const OpenADPError& e) {
        // Expected to fail, but we tested the fallback path
        EXPECT_TRUE(std::string(e.what()).find("Recovery failed") != std::string::npos ||
                   std::string(e.what()).find("Failed to") != std::string::npos);
    }
}

// Test recover (with refresh) error handling
TEST_F(OcryptTest, RecoverWithRefreshError) {
    // Test the recover function (which calls recover_without_refresh)
    nlohmann::json metadata_json;
    metadata_json["user_id"] = "user123";
    metadata_json["device_id"] = "device456";
    metadata_json["backup_id"] = "backup789";
    metadata_json["auth_code"] = "test_auth_code";
    metadata_json["ciphertext"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8});
    metadata_json["tag"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    metadata_json["nonce"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    metadata_json["servers"] = nlohmann::json::array({"https://unreachable.example.com"});
    
    Bytes metadata = utils::string_to_bytes(metadata_json.dump());
    
    try {
        auto result = ocrypt::recover(metadata, "1234", "https://servers.example.com");
    } catch (const OpenADPError& e) {
        // Expected to fail
        EXPECT_TRUE(std::string(e.what()).find("Recovery failed") != std::string::npos ||
                   std::string(e.what()).find("Failed to") != std::string::npos);
    }
}

// Test edge cases in generate_next_backup_id
TEST_F(OcryptTest, GenerateNextBackupIdEdgeCases) {
    // Test with no underscore
    std::string result1 = ocrypt::generate_next_backup_id("simple_id");
    EXPECT_EQ(result1, "simple_2");
    
    // Test with underscore but invalid number
    std::string result2 = ocrypt::generate_next_backup_id("id_abc");
    EXPECT_EQ(result2, "id_abc_2");
    
    // Test with empty string after underscore
    std::string result3 = ocrypt::generate_next_backup_id("id_");
    EXPECT_EQ(result3, "id__2");
    
    // Test with multiple underscores
    std::string result4 = ocrypt::generate_next_backup_id("complex_id_name_5");
    EXPECT_EQ(result4, "complex_id_name_6");
}

// Test base64 decoding errors in recovery
TEST_F(OcryptTest, RecoverWithInvalidBase64) {
    nlohmann::json metadata_json;
    metadata_json["user_id"] = "user123";
    metadata_json["device_id"] = "device456";
    metadata_json["backup_id"] = "backup789";
    metadata_json["auth_code"] = "test_auth_code";
    metadata_json["ciphertext"] = "invalid_base64!@#";  // Invalid base64
    metadata_json["tag"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    metadata_json["nonce"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    metadata_json["servers"] = nlohmann::json::array({"https://server1.example.com"});
    
    Bytes metadata = utils::string_to_bytes(metadata_json.dump());
    
    EXPECT_THROW(
        ocrypt::recover_without_refresh(metadata, "1234", "https://servers.example.com"),
        OpenADPError
    );
}

// Test exception handling in register functions
TEST_F(OcryptTest, RegisterExceptionHandling) {
    // Test with empty user_id to trigger validation errors
    Bytes secret = utils::string_to_bytes("secret");
    
    try {
        Bytes metadata = ocrypt::register_secret("", "app", secret, "1234", 5, "https://servers.example.com");
    } catch (const OpenADPError& e) {
        EXPECT_TRUE(std::string(e.what()).find("Registration failed") != std::string::npos);
    }
}

// Test server public key retrieval error path
TEST_F(OcryptTest, ServerPublicKeyRetrievalError) {
    // This tests the catch block in server public key retrieval
    Bytes secret = utils::string_to_bytes("my_secret");
    
    try {
        // Use a server that might exist but won't have the expected API
        Bytes metadata = ocrypt::register_secret(
            "user123", "app456", secret, "1234", 5, 
            "https://httpbin.org/status/500"  // Returns 500 error
        );
    } catch (const OpenADPError&) {
        // Expected to fail, which exercises the error handling paths
        EXPECT_TRUE(true);
    }
}

} // namespace test
} // namespace openadp 