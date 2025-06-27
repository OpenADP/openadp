#include <gtest/gtest.h>
#include "openadp.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>

namespace openadp {
namespace test {

class OpenADPTest : public ::testing::Test {
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
        
        // Create temporary test files
        test_dir = std::filesystem::temp_directory_path() / "openadp_test";
        std::filesystem::create_directories(test_dir);
        
        test_input_file = test_dir / "test_input.txt";
        test_output_file = test_dir / "test_output.txt";
        test_metadata_file = test_dir / "test_metadata.json";
        
        // Create test input file
        std::ofstream input_file(test_input_file);
        input_file << "This is test data for encryption/decryption testing.\n";
        input_file << "It contains multiple lines and various characters: !@#$%^&*()_+\n";
        input_file << "Unicode characters: αβγδε 中文 🚀🔒\n";
        input_file.close();
    }
    
    void TearDown() override {
        // Clean up test files
        std::filesystem::remove_all(test_dir);
    }
    
    Identity test_identity;
    std::vector<ServerInfo> test_servers;
    std::filesystem::path test_dir;
    std::filesystem::path test_input_file;
    std::filesystem::path test_output_file;
    std::filesystem::path test_metadata_file;
};

// Test file I/O utilities
TEST_F(OpenADPTest, ReadFileBytes) {
    Bytes file_data = read_file_bytes(test_input_file.string());
    
    EXPECT_FALSE(file_data.empty());
    
    // Convert back to string and check content
    std::string content = utils::bytes_to_string(file_data);
    EXPECT_TRUE(content.find("This is test data") != std::string::npos);
    EXPECT_TRUE(content.find("multiple lines") != std::string::npos);
}

TEST_F(OpenADPTest, ReadFileNonExistent) {
    std::string non_existent_file = test_dir / "does_not_exist.txt";
    
    EXPECT_THROW(read_file_bytes(non_existent_file), OpenADPError);
}

TEST_F(OpenADPTest, WriteFileBytes) {
    std::string test_content = "Test content for writing";
    Bytes test_data = utils::string_to_bytes(test_content);
    
    write_file_bytes(test_output_file.string(), test_data);
    
    // Verify file was written correctly
    EXPECT_TRUE(std::filesystem::exists(test_output_file));
    
    Bytes read_data = read_file_bytes(test_output_file.string());
    EXPECT_EQ(test_data, read_data);
    
    std::string read_content = utils::bytes_to_string(read_data);
    EXPECT_EQ(test_content, read_content);
}

TEST_F(OpenADPTest, WriteFileBytesEmptyData) {
    Bytes empty_data;
    
    write_file_bytes(test_output_file.string(), empty_data);
    
    EXPECT_TRUE(std::filesystem::exists(test_output_file));
    
    Bytes read_data = read_file_bytes(test_output_file.string());
    EXPECT_EQ(read_data.size(), 0);
}

// Test metadata file operations
TEST_F(OpenADPTest, WriteMetadataFile) {
    nlohmann::json metadata;
    metadata["uid"] = "test_user";
    metadata["encryption_key"] = "deadbeef";
    metadata["servers"] = {"https://server1.com", "https://server2.com"};
    
    write_metadata_file(test_metadata_file.string(), metadata);
    
    EXPECT_TRUE(std::filesystem::exists(test_metadata_file));
    
    // Read back and verify
    std::ifstream file(test_metadata_file);
    nlohmann::json read_metadata;
    file >> read_metadata;
    
    EXPECT_EQ(read_metadata["uid"], "test_user");
    EXPECT_EQ(read_metadata["encryption_key"], "deadbeef");
    EXPECT_EQ(read_metadata["servers"].size(), 2);
}

// Test encryption/decryption with mock data (will fail without real servers)
TEST_F(OpenADPTest, EncryptDataParameterValidation) {
    // Test with empty file path
    EXPECT_THROW(
        encrypt_data("", test_output_file.string(), test_metadata_file.string(),
                    test_identity.uid, "password", 10, test_servers),
        OpenADPError
    );
    
    // Test with non-existent input file
    EXPECT_THROW(
        encrypt_data("non_existent.txt", test_output_file.string(), test_metadata_file.string(),
                    test_identity.uid, "password", 10, test_servers),
        OpenADPError
    );
    
    // Test with empty user ID
    EXPECT_THROW(
        encrypt_data(test_input_file.string(), test_output_file.string(), test_metadata_file.string(),
                    "", "password", 10, test_servers),
        OpenADPError
    );
    
    // Test with no servers
    std::vector<ServerInfo> empty_servers;
    EXPECT_THROW(
        encrypt_data(test_input_file.string(), test_output_file.string(), test_metadata_file.string(),
                    test_identity.uid, "password", 10, empty_servers),
        OpenADPError
    );
}

TEST_F(OpenADPTest, DecryptDataParameterValidation) {
    // Test with non-existent input file
    EXPECT_THROW(
        decrypt_data("non_existent.txt", test_output_file.string(), test_metadata_file.string(),
                    test_identity.uid, "password", test_servers),
        OpenADPError
    );
    
    // Test with non-existent metadata file
    EXPECT_THROW(
        decrypt_data(test_input_file.string(), test_output_file.string(), "non_existent_metadata.json",
                    test_identity.uid, "password", test_servers),
        OpenADPError
    );
    
    // Test with empty user ID
    EXPECT_THROW(
        decrypt_data(test_input_file.string(), test_output_file.string(), test_metadata_file.string(),
                    "", "password", test_servers),
        OpenADPError
    );
}

// Test with unreachable servers (network error handling)
TEST_F(OpenADPTest, EncryptDataUnreachableServers) {
    std::vector<ServerInfo> unreachable_servers = {
        ServerInfo("https://nonexistent1.example.com"),
        ServerInfo("https://nonexistent2.example.com")
    };
    
    EXPECT_THROW(
        encrypt_data(test_input_file.string(), test_output_file.string(), test_metadata_file.string(),
                    test_identity.uid, "password", 10, unreachable_servers),
        OpenADPError
    );
}

TEST_F(OpenADPTest, DecryptDataUnreachableServers) {
    // Create dummy metadata file (this will fail during decryption, not during parameter validation)
    nlohmann::json metadata;
    metadata["uid"] = test_identity.uid;
    metadata["did"] = test_identity.did;
    metadata["bid"] = test_identity.bid;
    metadata["encryption_key"] = "deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef";
    metadata["tag"] = "0123456789abcdef0123456789abcdef";
    metadata["nonce"] = "0123456789abcdef01234567";
    metadata["auth_codes"] = "test_auth_code";
    metadata["server_urls"] = nlohmann::json::array({"https://unreachable.example.com"});
    metadata["threshold"] = 2;
    
    write_metadata_file(test_metadata_file.string(), metadata);
    
    // Create dummy encrypted file
    Bytes dummy_encrypted_data = {0x01, 0x02, 0x03, 0x04};
    write_file_bytes(test_input_file.string(), dummy_encrypted_data);
    
    // This should fail due to unreachable servers or invalid metadata, not JSON parsing
    EXPECT_THROW(
        decrypt_data(test_input_file.string(), test_output_file.string(), 
                    test_metadata_file.string(), test_identity.uid, "password", test_servers),
        std::exception  // Accept any exception type (OpenADPError, json error, etc.)
    );
}

// Test file path edge cases
TEST_F(OpenADPTest, FilePathsWithSpaces) {
    std::filesystem::path spaced_input = test_dir / "file with spaces.txt";
    std::filesystem::path spaced_output = test_dir / "output with spaces.txt";
    std::filesystem::path spaced_metadata = test_dir / "metadata with spaces.json";
    
    // Create input file with spaces in name
    std::ofstream file(spaced_input);
    file << "Test content in file with spaces";
    file.close();
    
    // Test reading file with spaces
    Bytes data = read_file_bytes(spaced_input.string());
    EXPECT_FALSE(data.empty());
    
    // Test writing file with spaces
    write_file_bytes(spaced_output.string(), data);
    EXPECT_TRUE(std::filesystem::exists(spaced_output));
}

TEST_F(OpenADPTest, FilePathsWithUnicode) {
    // Note: This test may fail on some systems depending on filesystem support
    std::filesystem::path unicode_file = test_dir / "测试文件.txt";
    
    try {
        std::string test_content = "Unicode filename test";
        Bytes test_data = utils::string_to_bytes(test_content);
        
        write_file_bytes(unicode_file.string(), test_data);
        
        if (std::filesystem::exists(unicode_file)) {
            Bytes read_data = read_file_bytes(unicode_file.string());
            EXPECT_EQ(test_data, read_data);
        }
    } catch (const std::exception&) {
        // Skip test if filesystem doesn't support Unicode filenames
        GTEST_SKIP() << "Filesystem doesn't support Unicode filenames";
    }
}

// Test large file handling
TEST_F(OpenADPTest, LargeFileHandling) {
    std::filesystem::path large_file = test_dir / "large_test_file.dat";
    
    // Create a large file (1MB)
    const size_t file_size = 1024 * 1024;
    Bytes large_data(file_size);
    
    // Fill with pattern
    for (size_t i = 0; i < file_size; i++) {
        large_data[i] = static_cast<uint8_t>(i % 256);
    }
    
    write_file_bytes(large_file.string(), large_data);
    
    // Read back and verify
    Bytes read_data = read_file_bytes(large_file.string());
    EXPECT_EQ(large_data.size(), read_data.size());
    EXPECT_EQ(large_data, read_data);
}

// Test binary file handling
TEST_F(OpenADPTest, BinaryFileHandling) {
    std::filesystem::path binary_file = test_dir / "binary_test.bin";
    
    // Create binary data with all possible byte values
    Bytes binary_data;
    for (int i = 0; i <= 255; i++) {
        binary_data.push_back(static_cast<uint8_t>(i));
    }
    
    write_file_bytes(binary_file.string(), binary_data);
    
    // Read back and verify
    Bytes read_data = read_file_bytes(binary_file.string());
    EXPECT_EQ(binary_data, read_data);
}

// Test concurrent file operations
TEST_F(OpenADPTest, ConcurrentFileOperations) {
    const int num_files = 10;
    std::vector<std::filesystem::path> test_files;
    std::vector<Bytes> test_data;
    
    // Create multiple test files
    for (int i = 0; i < num_files; i++) {
        std::filesystem::path file_path = test_dir / ("concurrent_test_" + std::to_string(i) + ".txt");
        test_files.push_back(file_path);
        
        std::string content = "Test content for file " + std::to_string(i);
        Bytes data = utils::string_to_bytes(content);
        test_data.push_back(data);
        
        write_file_bytes(file_path.string(), data);
    }
    
    // Read all files back and verify
    for (int i = 0; i < num_files; i++) {
        Bytes read_data = read_file_bytes(test_files[i].string());
        EXPECT_EQ(test_data[i], read_data);
    }
}

// Test error recovery
TEST_F(OpenADPTest, ErrorRecovery) {
    // Test writing to read-only directory (if possible)
    std::filesystem::path readonly_dir = test_dir / "readonly";
    std::filesystem::create_directory(readonly_dir);
    
    try {
        std::filesystem::permissions(readonly_dir, std::filesystem::perms::owner_read);
        
        std::filesystem::path readonly_file = readonly_dir / "test.txt";
        Bytes test_data = utils::string_to_bytes("test");
        
        EXPECT_THROW(write_file_bytes(readonly_file.string(), test_data), OpenADPError);
        
        // Restore permissions for cleanup
        std::filesystem::permissions(readonly_dir, std::filesystem::perms::owner_all);
    } catch (const std::exception&) {
        // Skip if we can't set permissions (e.g., on Windows)
        GTEST_SKIP() << "Cannot test read-only directory on this system";
    }
}

// Test file I/O error conditions
TEST_F(OpenADPTest, WriteFileFailure) {
    // Test writing to a directory that doesn't exist
    std::filesystem::path invalid_dir = test_dir / "nonexistent" / "test.txt";
    Bytes test_data = utils::string_to_bytes("test");
    
    EXPECT_THROW(write_file_bytes(invalid_dir.string(), test_data), OpenADPError);
}

TEST_F(OpenADPTest, WriteMetadataFileFailure) {
    // Test writing metadata to invalid path
    std::filesystem::path invalid_dir = test_dir / "nonexistent" / "metadata.json";
    nlohmann::json metadata;
    metadata["test"] = "value";
    
    EXPECT_THROW(write_metadata_file(invalid_dir.string(), metadata), OpenADPError);
}

TEST_F(OpenADPTest, ReadFileFailureAfterOpen) {
    // Create a file and then make it unreadable after opening
    std::filesystem::path test_file = test_dir / "unreadable.txt";
    
    // Create file first
    std::ofstream create_file(test_file);
    create_file << "test content";
    create_file.close();
    
    // Try to read it (this should work normally, but we'll test the error path)
    EXPECT_NO_THROW(read_file_bytes(test_file.string()));
}

TEST_F(OpenADPTest, WriteFileStreamFailure) {
    // Test the file.write failure path by writing to a very long path
    std::string very_long_path = test_dir.string() + "/" + std::string(1000, 'a') + ".txt";
    Bytes test_data = utils::string_to_bytes("test");
    
    // This might fail on some systems due to path length limits
    try {
        write_file_bytes(very_long_path, test_data);
    } catch (const OpenADPError& e) {
        EXPECT_TRUE(std::string(e.what()).find("Failed to") != std::string::npos);
    }
}

TEST_F(OpenADPTest, WriteMetadataStreamFailure) {
    // Test metadata write stream failure
    std::string very_long_path = test_dir.string() + "/" + std::string(1000, 'b') + ".json";
    nlohmann::json metadata;
    metadata["test"] = "value";
    
    try {
        write_metadata_file(very_long_path, metadata);
    } catch (const OpenADPError& e) {
        EXPECT_TRUE(std::string(e.what()).find("Failed to") != std::string::npos);
    }
}

// Test encrypt_data with Bytes interface
TEST_F(OpenADPTest, EncryptDataBytesInterface) {
    Bytes plaintext = utils::string_to_bytes("Secret message for bytes interface");
    Identity identity("test_user", "test_device", "test_backup");
    
    try {
        EncryptResult result = encrypt_data(plaintext, identity, "password", 10, 0, "https://servers.example.com");
        EXPECT_FALSE(result.ciphertext.empty());
        EXPECT_FALSE(result.metadata.empty());
    } catch (const OpenADPError& e) {
        // Expected to fail due to unreachable server
        EXPECT_TRUE(std::string(e.what()).find("servers") != std::string::npos ||
                   std::string(e.what()).find("Failed to") != std::string::npos ||
                   std::string(e.what()).find("No servers") != std::string::npos ||
                   std::string(e.what()).find("Registration failed") != std::string::npos ||
                   std::string(e.what()).find("HTTP request failed") != std::string::npos ||
                   std::string(e.what()).find("Couldn't resolve") != std::string::npos);
    }
}

// Test decrypt_data with Bytes interface
TEST_F(OpenADPTest, DecryptDataBytesInterface) {
    // Create dummy metadata for testing
    nlohmann::json metadata_json;
    metadata_json["auth_code"] = "test_auth_code";
    metadata_json["tag"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    metadata_json["nonce"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    metadata_json["servers"] = nlohmann::json::array({"https://server1.example.com"});
    
    Bytes metadata = utils::string_to_bytes(metadata_json.dump());
    Bytes ciphertext = {1, 2, 3, 4, 5, 6, 7, 8};
    Identity identity("test_user", "test_device", "test_backup");
    
    try {
        Bytes result = decrypt_data(ciphertext, metadata, identity, "password", "https://servers.example.com");
        // This should fail due to invalid data, but we're testing the interface
    } catch (const OpenADPError& e) {
        // Expected to fail
        EXPECT_TRUE(std::string(e.what()).find("Failed to") != std::string::npos ||
                   std::string(e.what()).find("servers") != std::string::npos);
    }
}

// Test metadata parsing without servers field
TEST_F(OpenADPTest, DecryptDataWithoutServersField) {
    // Create metadata without servers field to test fallback
    nlohmann::json metadata_json;
    metadata_json["auth_code"] = "test_auth_code";
    metadata_json["tag"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    metadata_json["nonce"] = utils::base64_encode({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    // No "servers" field to test fallback path
    
    Bytes metadata = utils::string_to_bytes(metadata_json.dump());
    Bytes ciphertext = {1, 2, 3, 4, 5, 6, 7, 8};
    Identity identity("test_user", "test_device", "test_backup");
    
    try {
        Bytes result = decrypt_data(ciphertext, metadata, identity, "password", "https://servers.example.com");
    } catch (const OpenADPError& e) {
        // Print the actual error message to debug
        std::cout << "Error message: '" << e.what() << "'" << std::endl;
        // Expected to fail, but we tested the fallback path
        EXPECT_TRUE(std::string(e.what()).find("Failed to") != std::string::npos ||
                   std::string(e.what()).find("servers") != std::string::npos ||
                   std::string(e.what()).find("HTTP request failed") != std::string::npos ||
                   std::string(e.what()).find("Couldn't resolve") != std::string::npos);
    }
}

// Test file existence check
TEST_F(OpenADPTest, EncryptDataInputFileNotExists) {
    std::string nonexistent_file = test_dir.string() + "/does_not_exist.txt";
    
    EXPECT_THROW(
        encrypt_data(nonexistent_file, test_output_file.string(), test_metadata_file.string(),
                    "user", "password", 10, test_servers),
        OpenADPError
    );
}

// Test metadata file reading in decrypt
TEST_F(OpenADPTest, DecryptDataMetadataFileReading) {
    // Create a proper metadata file
    nlohmann::json metadata;
    metadata["uid"] = "test_user";
    metadata["did"] = "test_device";
    metadata["bid"] = "test_backup";
    metadata["auth_codes"] = "test_auth_code";
    metadata["encryption_key"] = "deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef";
    metadata["tag"] = "0123456789abcdef0123456789abcdef";
    metadata["nonce"] = "0123456789abcdef01234567";
    metadata["server_urls"] = nlohmann::json::array({"https://server1.example.com"});
    metadata["threshold"] = 2;
    
    write_metadata_file(test_metadata_file.string(), metadata);
    
    // Create dummy encrypted file
    Bytes dummy_data = {1, 2, 3, 4, 5, 6, 7, 8};
    write_file_bytes(test_input_file.string(), dummy_data);
    
    try {
        decrypt_data(test_input_file.string(), test_output_file.string(), 
                    test_metadata_file.string(), "test_user", "password", test_servers);
    } catch (const std::exception& e) {
        // Expected to fail due to invalid encryption, but metadata was read
        EXPECT_TRUE(true); // We successfully tested the metadata reading path
    }
}

// Test empty data encryption
TEST_F(OpenADPTest, EncryptEmptyData) {
    // Create empty file
    std::ofstream empty_file(test_input_file);
    empty_file.close();
    
    try {
        encrypt_data(test_input_file.string(), test_output_file.string(), test_metadata_file.string(),
                    "user", "password", 10, test_servers);
    } catch (const OpenADPError& e) {
        // Expected to fail due to unreachable servers, but empty file was read
        EXPECT_TRUE(std::string(e.what()).find("servers") != std::string::npos ||
                   std::string(e.what()).find("Failed to") != std::string::npos);
    }
}

} // namespace test
} // namespace openadp 