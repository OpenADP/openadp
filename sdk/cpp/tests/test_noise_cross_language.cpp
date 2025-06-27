#include <gtest/gtest.h>
#include "openadp/noise.hpp"
#include "openadp/utils.hpp"
#include "openadp/crypto.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace openadp {
namespace test {

class NoiseNKCrossLanguageTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    
    // Helper to send length-prefixed message
    bool send_message(int socket_fd, const Bytes& data) {
        uint32_t length = htonl(data.size());
        
        // Send length
        if (send(socket_fd, &length, 4, 0) != 4) {
            return false;
        }
        
        // Send data
        if (send(socket_fd, data.data(), data.size(), 0) != static_cast<ssize_t>(data.size())) {
            return false;
        }
        
        return true;
    }
    
    // Helper to receive length-prefixed message
    Bytes receive_message(int socket_fd) {
        uint32_t length;
        
        // Receive length
        if (recv(socket_fd, &length, 4, MSG_WAITALL) != 4) {
            return Bytes{};
        }
        
        length = ntohl(length);
        if (length > 1024 * 1024) { // 1MB limit
            return Bytes{};
        }
        
        // Receive data
        Bytes data(length);
        if (recv(socket_fd, data.data(), length, MSG_WAITALL) != static_cast<ssize_t>(length)) {
            return Bytes{};
        }
        
        return data;
    }
};

TEST_F(NoiseNKCrossLanguageTest, ConnectToPythonServer) {
    // This test requires the Python server to be running
    // Start it with: cd sdk/python && python noise_server.py
    
    // Read server info
    std::ifstream server_info_file("../../../sdk/python/server_info.json");
    if (!server_info_file.is_open()) {
        GTEST_SKIP() << "Python server not running (server_info.json not found)";
        return;
    }
    
    std::string server_info_json((std::istreambuf_iterator<char>(server_info_file)),
                                 std::istreambuf_iterator<char>());
    server_info_file.close();
    
    // Extract server public key (simplified JSON parsing)
    size_t key_start = server_info_json.find("\"public_key\": \"") + 15;
    size_t key_end = server_info_json.find("\"", key_start);
    
    if (key_start == std::string::npos || key_end == std::string::npos) {
        GTEST_SKIP() << "Could not parse server public key from server_info.json";
        return;
    }
    
    std::string server_public_key_hex = server_info_json.substr(key_start, key_end - key_start);
    Bytes server_public_key = crypto::hex_to_bytes(server_public_key_hex);
    
    std::cout << "🔐 Server public key: " << server_public_key_hex.substr(0, 32) << "..." << std::endl;
    
    // Connect to server
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0) << "Failed to create socket";
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    int connect_result = connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (connect_result < 0) {
        close(socket_fd);
        GTEST_SKIP() << "Could not connect to Python server (is it running?)";
        return;
    }
    
    std::cout << "✅ Connected to Python server" << std::endl;
    
    // Initialize Noise-NK client
    noise::NoiseState client;
    client.initialize_handshake(server_public_key);
    
    // Send first handshake message
    Bytes client_message = client.write_message();
    std::cout << "📤 Sending handshake message 1: " << client_message.size() << " bytes" << std::endl;
    
    ASSERT_TRUE(send_message(socket_fd, client_message)) << "Failed to send handshake message";
    
    // Receive second handshake message
    Bytes server_message = receive_message(socket_fd);
    ASSERT_FALSE(server_message.empty()) << "Failed to receive server handshake message";
    
    std::cout << "📨 Received handshake message 2: " << server_message.size() << " bytes" << std::endl;
    
    // Process server message
    ASSERT_NO_THROW(client.read_message(server_message)) << "Failed to process server handshake message";
    
    ASSERT_TRUE(client.handshake_finished()) << "Handshake not completed";
    
    std::cout << "✅ Noise-NK handshake completed successfully!" << std::endl;
    
    // Test secure communication
    std::string test_message = "Hello from C++ client!";
    Bytes plaintext = utils::string_to_bytes(test_message);
    Bytes encrypted = client.encrypt(plaintext);
    
    std::cout << "📤 Sending secure message: " << test_message << std::endl;
    ASSERT_TRUE(send_message(socket_fd, encrypted)) << "Failed to send encrypted message";
    
    // Receive response
    Bytes encrypted_response = receive_message(socket_fd);
    ASSERT_FALSE(encrypted_response.empty()) << "Failed to receive encrypted response";
    
    Bytes decrypted_response = client.decrypt(encrypted_response);
    std::string response = utils::bytes_to_string(decrypted_response);
    
    std::cout << "📨 Received secure response: " << response << std::endl;
    
    // Should be an echo
    EXPECT_TRUE(response.find(test_message) != std::string::npos) << "Response should contain original message";
    EXPECT_TRUE(response.find("Python server") != std::string::npos) << "Response should indicate Python server";
    
    close(socket_fd);
    
    std::cout << "🎉 C++ client successfully communicated with Python server!" << std::endl;
}

} // namespace test
} // namespace openadp 