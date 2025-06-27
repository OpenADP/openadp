#include <gtest/gtest.h>
#include "openadp/noise.hpp"
#include "openadp/utils.hpp"
#include "openadp/crypto.hpp"
#include <iostream>

namespace openadp {
namespace test {

class NoiseDebugTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NoiseDebugTest, CompareWithJavaScript) {
    // Use the same server public key as JavaScript client for comparison
    std::string server_public_key_hex = "c021e3aa028b5c699e01733b36b331ae8e15a970dd5d36fab1b4833574e95e0f";
    Bytes server_public_key = crypto::hex_to_bytes(server_public_key_hex);
    
    std::cout << "🔐 Using server public key: " << server_public_key_hex << std::endl;
    
    // Initialize C++ Noise-NK client
    noise::NoiseState client;
    client.initialize_handshake(server_public_key);
    
    // Generate first handshake message
    Bytes client_message = client.write_message();
    
    std::cout << "📤 C++ handshake message 1: " << client_message.size() << " bytes" << std::endl;
    std::cout << "🔍 C++ message hex: " << crypto::bytes_to_hex(client_message) << std::endl;
    
    // JavaScript sends: da3e75710adf2b99428d29ff9c0cc70795ce2396015fd8a105cb30e3cec2c80121883eb6539fe2a8b3ed7be0d198edd5
    std::string js_message_hex = "da3e75710adf2b99428d29ff9c0cc70795ce2396015fd8a105cb30e3cec2c80121883eb6539fe2a8b3ed7be0d198edd5";
    std::cout << "🔍 JS message hex:  " << js_message_hex << std::endl;
    
    // Compare structure
    if (client_message.size() == 48) {
        Bytes ephemeral_key(client_message.begin(), client_message.begin() + 32);
        Bytes encrypted_payload(client_message.begin() + 32, client_message.end());
        
        std::cout << "✅ C++ message structure correct: 32 bytes ephemeral + 16 bytes encrypted payload" << std::endl;
        std::cout << "🔑 C++ ephemeral key: " << crypto::bytes_to_hex(ephemeral_key) << std::endl;
        std::cout << "🔒 C++ encrypted payload: " << crypto::bytes_to_hex(encrypted_payload) << std::endl;
    } else {
        std::cout << "❌ C++ message structure incorrect: expected 48 bytes, got " << client_message.size() << std::endl;
    }
    
    // Test handshake hash
    Bytes handshake_hash = client.get_handshake_hash();
    std::cout << "🔑 C++ handshake hash: " << crypto::bytes_to_hex(handshake_hash) << std::endl;
    
    // JavaScript shows: bbb890ee4745d76bde86eaf9b23c8c3ed381329078f5429b3935e6f72c030e2f
    std::string js_hash_hex = "bbb890ee4745d76bde86eaf9b23c8c3ed381329078f5429b3935e6f72c030e2f";
    std::cout << "🔑 JS handshake hash:  " << js_hash_hex << std::endl;
    
    EXPECT_EQ(client_message.size(), 48) << "Message should be 48 bytes (32 ephemeral + 16 encrypted)";
}

TEST_F(NoiseDebugTest, TestHandshakeFlow) {
    // Test the complete handshake flow with deterministic keys for debugging
    std::cout << "\n🔬 Testing complete handshake flow..." << std::endl;
    
    // Generate server keys
    Bytes server_private = noise::generate_keypair_private();
    Bytes server_public = noise::derive_public_key(server_private);
    
    std::cout << "🔑 Server private: " << crypto::bytes_to_hex(server_private) << std::endl;
    std::cout << "🔑 Server public:  " << crypto::bytes_to_hex(server_public) << std::endl;
    
    // Initialize client and server
    noise::NoiseState client, server;
    client.initialize_handshake(server_public);
    server.initialize_responder(server_private);
    
    // Step 1: Client -> Server
    Bytes client_message = client.write_message();
    std::cout << "\n📤 Client message: " << client_message.size() << " bytes" << std::endl;
    std::cout << "🔍 Client message hex: " << crypto::bytes_to_hex(client_message) << std::endl;
    
    // Server processes client message
    Bytes client_payload = server.read_message(client_message);
    std::cout << "📝 Client payload size: " << client_payload.size() << " bytes" << std::endl;
    
    // Step 2: Server -> Client
    Bytes server_message = server.write_message();
    std::cout << "\n📤 Server message: " << server_message.size() << " bytes" << std::endl;
    std::cout << "🔍 Server message hex: " << crypto::bytes_to_hex(server_message) << std::endl;
    
    // Client processes server message
    Bytes server_payload = client.read_message(server_message);
    std::cout << "📝 Server payload size: " << server_payload.size() << " bytes" << std::endl;
    
    // Check handshake completion
    std::cout << "\n✅ Client handshake finished: " << (client.handshake_finished() ? "true" : "false") << std::endl;
    std::cout << "✅ Server handshake finished: " << (server.handshake_finished() ? "true" : "false") << std::endl;
    
    // Test transport encryption
    if (client.handshake_finished() && server.handshake_finished()) {
        std::string test_message = "Hello Noise!";
        Bytes plaintext = utils::string_to_bytes(test_message);
        
        Bytes encrypted = client.encrypt(plaintext);
        Bytes decrypted = server.decrypt(encrypted);
        
        std::string result = utils::bytes_to_string(decrypted);
        std::cout << "🔐 Transport test: '" << test_message << "' -> '" << result << "'" << std::endl;
        
        EXPECT_EQ(test_message, result) << "Transport encryption should work";
    }
    
    EXPECT_TRUE(client.handshake_finished()) << "Client handshake should be finished";
    EXPECT_TRUE(server.handshake_finished()) << "Server handshake should be finished";
}

TEST_F(NoiseDebugTest, StepByStepHashTracking) {
    std::cout << "\n🔬 Step-by-step hash tracking..." << std::endl;
    
    // Use the same server public key as JavaScript
    std::string server_public_key_hex = "c021e3aa028b5c699e01733b36b331ae8e15a970dd5d36fab1b4833574e95e0f";
    Bytes server_public_key = crypto::hex_to_bytes(server_public_key_hex);
    
    // Manual step-by-step initialization to match JavaScript exactly
    std::string protocol_name = "Noise_NK_25519_AESGCM_SHA256";
    Bytes protocol_bytes = utils::string_to_bytes(protocol_name);
    
    Bytes h;
    if (protocol_bytes.size() <= 32) {
        h = protocol_bytes;
        h.resize(32, 0);
    } else {
        h = crypto::sha256_hash(protocol_bytes);
    }
    
    std::cout << "🔑 Initial hash (protocol): " << crypto::bytes_to_hex(h) << std::endl;
    
    // Mix empty prologue
    Bytes prologue; // Empty
    Bytes combined = h;
    combined.insert(combined.end(), prologue.begin(), prologue.end());
    h = crypto::sha256_hash(combined);
    
    std::cout << "🔑 After prologue mix: " << crypto::bytes_to_hex(h) << std::endl;
    
    // Mix server public key
    combined = h;
    combined.insert(combined.end(), server_public_key.begin(), server_public_key.end());
    h = crypto::sha256_hash(combined);
    
    std::cout << "🔑 After server key mix: " << crypto::bytes_to_hex(h) << std::endl;
    
    // Now compare with our NoiseState
    noise::NoiseState client;
    client.initialize_handshake(server_public_key);
    Bytes client_hash = client.get_handshake_hash();
    
    std::cout << "🔑 NoiseState hash: " << crypto::bytes_to_hex(client_hash) << std::endl;
    
    EXPECT_EQ(crypto::bytes_to_hex(h), crypto::bytes_to_hex(client_hash)) << "Manual hash should match NoiseState hash";
    
    // Now test with a fixed ephemeral key to compare with JavaScript
    // JavaScript ephemeral key from the example: da3e75710adf2b99428d29ff9c0cc70795ce2396015fd8a105cb30e3cec2c801
    std::string js_ephemeral_hex = "da3e75710adf2b99428d29ff9c0cc70795ce2396015fd8a105cb30e3cec2c801";
    Bytes js_ephemeral = crypto::hex_to_bytes(js_ephemeral_hex);
    
    // Mix ephemeral key
    combined = h;
    combined.insert(combined.end(), js_ephemeral.begin(), js_ephemeral.end());
    h = crypto::sha256_hash(combined);
    
    std::cout << "🔑 After ephemeral mix: " << crypto::bytes_to_hex(h) << std::endl;
    
    // Note: JavaScript shows hash AFTER complete message processing, which includes:
    // 1. Mix ephemeral key (done above)
    // 2. Perform DH and mix key
    // 3. Encrypt payload and mix hash with ciphertext
    
    // Let's manually do the DH step
    std::string js_ephemeral_private_hex = "da3e75710adf2b99428d29ff9c0cc70795ce2396015fd8a105cb30e3cec2c801"; // This is wrong - we need the private key
    
    std::cout << "🔑 JS shows hash after complete message 1 processing" << std::endl;
    std::cout << "🔑 JS expected hash: bbb890ee4745d76bde86eaf9b23c8c3ed381329078f5429b3935e6f72c030e2f" << std::endl;
    
    // For now, let's just verify our hash up to ephemeral mixing is consistent
    // The full message processing hash will be different due to different DH results
}

} // namespace test
} // namespace openadp 