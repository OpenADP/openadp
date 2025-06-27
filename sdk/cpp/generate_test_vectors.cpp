#include <iostream>
#include <iomanip>
#include <fstream>
#include <nlohmann/json.hpp>
#include "openadp/crypto.hpp"
#include "openadp/utils.hpp"

using namespace openadp;
using json = nlohmann::json;

// Helper function to format bytes as hex string
std::string bytes_to_hex_string(const Bytes& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Helper to create JSON from Point4D
json point_to_json(const Point4D& point) {
    json json_point;
    json_point["x"] = point.x;
    json_point["y"] = point.y;
    json_point["z"] = point.z;
    json_point["t"] = point.t;
    return json_point;
}

int main() {
    json test_vectors;
    
    // Metadata
    test_vectors["metadata"]["version"] = "1.0";
    test_vectors["metadata"]["description"] = "OpenADP Test Vectors Generated from C++ Implementation";
    test_vectors["metadata"]["generator"] = "C++ SDK";
    test_vectors["metadata"]["timestamp"] = "2024-12-19";
    
    std::cout << "🧪 Generating OpenADP Test Vectors..." << std::endl;
    
    // SHA256 Test Vectors
    std::cout << "📝 Generating SHA256 test vectors..." << std::endl;
    json sha256_vectors = json::array();
    
    struct SHA256TestCase {
        std::string description;
        std::string input;
    };
    
    std::vector<SHA256TestCase> sha256_cases = {
        {"Empty string", ""},
        {"Hello World", "Hello World"},
        {"Single byte", "a"},
        {"OpenADP test", "OpenADP test vector"},
        {"Unicode", "用户设备备份"}
    };
    
    for (const auto& test_case : sha256_cases) {
        json vector;
        vector["description"] = test_case.description;
        vector["input"] = test_case.input;
        
        Bytes input_bytes = utils::string_to_bytes(test_case.input);
        vector["input_hex"] = bytes_to_hex_string(input_bytes);
        
        Bytes hash = crypto::sha256_hash(input_bytes);
        vector["expected"] = bytes_to_hex_string(hash);
        
        sha256_vectors.push_back(vector);
    }
    test_vectors["sha256_vectors"] = sha256_vectors;
    
    // Prefixed Function Test Vectors
    std::cout << "📦 Generating prefixed function test vectors..." << std::endl;
    json prefixed_vectors = json::array();
    
    std::vector<std::string> prefixed_cases = {"", "Hello", "OpenADP", "A longer test string"};
    
    for (const auto& input : prefixed_cases) {
        json vector;
        vector["description"] = input.empty() ? "Empty data" : "Data: " + input;
        vector["input"] = input;
        
        Bytes input_bytes = utils::string_to_bytes(input);
        vector["input_hex"] = bytes_to_hex_string(input_bytes);
        
        Bytes prefixed = crypto::prefixed(input_bytes);
        vector["expected_hex"] = bytes_to_hex_string(prefixed);
        vector["length"] = static_cast<int>(input_bytes.size());
        
        prefixed_vectors.push_back(vector);
    }
    test_vectors["prefixed_vectors"] = prefixed_vectors;
    
    // Ed25519 Hash-to-Point Test Vectors
    std::cout << "🔑 Generating Ed25519 hash-to-point test vectors..." << std::endl;
    json hash_to_point_vectors = json::array();
    
    struct HashToPointTestCase {
        std::string description;
        std::string uid, did, bid, pin;
    };
    
    std::vector<HashToPointTestCase> h2p_cases = {
        {"Basic test", "user", "device", "backup", "1234"},
        {"Empty inputs", "", "", "", ""},
        {"Single chars", "u", "d", "b", "p"},
        {"Long inputs", "very-long-user-identifier", "device-with-long-name", "backup-id-with-timestamp", "complex-pin-12345"},
        {"Unicode inputs", "用户", "设备", "备份", "密码"}
    };
    
    for (const auto& test_case : h2p_cases) {
        json vector;
        vector["description"] = test_case.description;
        
        // Input strings
        json inputs;
        inputs["uid"] = test_case.uid;
        inputs["did"] = test_case.did;
        inputs["bid"] = test_case.bid;
        inputs["pin"] = test_case.pin;
        vector["inputs"] = inputs;
        
        // Input hex
        json inputs_hex;
        inputs_hex["uid"] = bytes_to_hex_string(utils::string_to_bytes(test_case.uid));
        inputs_hex["did"] = bytes_to_hex_string(utils::string_to_bytes(test_case.did));
        inputs_hex["bid"] = bytes_to_hex_string(utils::string_to_bytes(test_case.bid));
        inputs_hex["pin"] = bytes_to_hex_string(utils::string_to_bytes(test_case.pin));
        vector["inputs_hex"] = inputs_hex;
        
        // Compute hash-to-point
        Bytes uid_bytes = utils::string_to_bytes(test_case.uid);
        Bytes did_bytes = utils::string_to_bytes(test_case.did);
        Bytes bid_bytes = utils::string_to_bytes(test_case.bid);
        Bytes pin_bytes = utils::string_to_bytes(test_case.pin);
        
        Point4D result = crypto::Ed25519::hash_to_point(uid_bytes, did_bytes, bid_bytes, pin_bytes);
        vector["expected_point"] = point_to_json(result);
        
        // Also include compressed form
        Bytes compressed = crypto::Ed25519::compress(result);
        vector["expected_compressed_hex"] = bytes_to_hex_string(compressed);
        
        hash_to_point_vectors.push_back(vector);
    }
    test_vectors["ed25519"]["hash_to_point_vectors"] = hash_to_point_vectors;
    
    // Ed25519 Point Operations
    std::cout << "➕ Generating Ed25519 point operation test vectors..." << std::endl;
    
    // Base point
    Bytes uid = utils::string_to_bytes("base");
    Bytes did = utils::string_to_bytes("point");
    Bytes bid = utils::string_to_bytes("test");
    Bytes pin = utils::string_to_bytes("0");
    Point4D base_point = crypto::Ed25519::hash_to_point(uid, did, bid, pin);
    
    test_vectors["ed25519"]["base_point_example"] = point_to_json(base_point);
    test_vectors["ed25519"]["base_point_compressed"] = bytes_to_hex_string(crypto::Ed25519::compress(base_point));
    
    // Point addition: base_point + base_point
    Point4D doubled = crypto::Ed25519::point_add(base_point, base_point);
    test_vectors["ed25519"]["point_addition_example"]["point1"] = point_to_json(base_point);
    test_vectors["ed25519"]["point_addition_example"]["point2"] = point_to_json(base_point);
    test_vectors["ed25519"]["point_addition_example"]["result"] = point_to_json(doubled);
    
    // Scalar multiplication: 2 * base_point
    Point4D scalar_mult = crypto::Ed25519::scalar_mult("2", base_point);
    test_vectors["ed25519"]["scalar_multiplication_example"]["scalar"] = "2";
    test_vectors["ed25519"]["scalar_multiplication_example"]["point"] = point_to_json(base_point);
    test_vectors["ed25519"]["scalar_multiplication_example"]["result"] = point_to_json(scalar_mult);
    
    // Verify they match
    bool addition_equals_scalar = (doubled.x == scalar_mult.x && doubled.y == scalar_mult.y && 
                                   doubled.z == scalar_mult.z && doubled.t == scalar_mult.t);
    test_vectors["ed25519"]["point_operations_consistent"] = addition_equals_scalar;
    
    // HKDF Test Vectors
    std::cout << "🔐 Generating HKDF test vectors..." << std::endl;
    json hkdf_vectors = json::array();
    
    struct HKDFTestCase {
        std::string description;
        std::string input_key_hex;
        std::string salt_hex;
        std::string info_hex;
        size_t output_length;
    };
    
    std::vector<HKDFTestCase> hkdf_cases = {
        {"Basic HKDF", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42},
        {"Empty salt", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 32},
        {"Short output", "deadbeefcafebabe", "73616c74", "696e666f", 16}
    };
    
    for (const auto& test_case : hkdf_cases) {
        json vector;
        vector["description"] = test_case.description;
        vector["input_key_hex"] = test_case.input_key_hex;
        vector["salt_hex"] = test_case.salt_hex;
        vector["info_hex"] = test_case.info_hex;
        vector["output_length"] = static_cast<int>(test_case.output_length);
        
        Bytes input_key = utils::hex_decode(test_case.input_key_hex);
        Bytes salt = utils::hex_decode(test_case.salt_hex);
        Bytes info = utils::hex_decode(test_case.info_hex);
        
        Bytes output = crypto::hkdf_derive(input_key, salt, info, test_case.output_length);
        vector["expected_hex"] = bytes_to_hex_string(output);
        
        hkdf_vectors.push_back(vector);
    }
    test_vectors["hkdf_vectors"] = hkdf_vectors;
    
    // AES-GCM Test Vectors (with fixed nonce for reproducibility)
    std::cout << "🔒 Generating AES-GCM test vectors..." << std::endl;
    json aes_gcm_vectors = json::array();
    
    // Fixed key and nonce for reproducible results
    Bytes fixed_key = utils::hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Bytes fixed_nonce = utils::hex_decode("000000000000000000000000");
    
    std::vector<std::string> aes_test_messages = {
        "",
        "Hello",
        "This is a secret message",
        "OpenADP encryption test with a longer message"
    };
    
    for (const auto& message : aes_test_messages) {
        json vector;
        vector["description"] = message.empty() ? "Empty message" : "Message: " + message.substr(0, 20) + (message.length() > 20 ? "..." : "");
        vector["plaintext"] = message;
        
        Bytes plaintext = utils::string_to_bytes(message);
        vector["plaintext_hex"] = bytes_to_hex_string(plaintext);
        vector["key_hex"] = bytes_to_hex_string(fixed_key);
        vector["nonce_hex"] = bytes_to_hex_string(fixed_nonce);
        
        auto result = crypto::aes_gcm_encrypt(plaintext, fixed_key, fixed_nonce, Bytes{});
        vector["expected_ciphertext_hex"] = bytes_to_hex_string(result.ciphertext);
        vector["expected_tag_hex"] = bytes_to_hex_string(result.tag);
        
        aes_gcm_vectors.push_back(vector);
    }
    test_vectors["aes_gcm_vectors"] = aes_gcm_vectors;
    
    // Shamir Secret Sharing Test Vectors
    std::cout << "🔢 Generating Shamir Secret Sharing test vectors..." << std::endl;
    json shamir_vectors = json::array();
    
    struct ShamirTestCase {
        std::string description;
        std::string secret_hex;
        int threshold;
        int num_shares;
    };
    
    std::vector<ShamirTestCase> shamir_cases = {
        {"Basic 2-of-3", "deadbeef", 2, 3},
        {"Minimum 2-of-2", "cafebabe", 2, 2},
        {"Large secret 3-of-5", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", 3, 5}
    };
    
    for (const auto& test_case : shamir_cases) {
        json vector;
        vector["description"] = test_case.description;
        vector["secret_hex"] = test_case.secret_hex;
        vector["threshold"] = test_case.threshold;
        vector["num_shares"] = test_case.num_shares;
        
        auto shares = crypto::ShamirSecretSharing::split_secret(test_case.secret_hex, test_case.threshold, test_case.num_shares);
        
        json shares_json = json::array();
        for (const auto& share : shares) {
            json share_json;
            share_json["x"] = share.x;
            share_json["y"] = share.y;
            shares_json.push_back(share_json);
        }
        vector["shares"] = shares_json;
        
        // Test recovery with minimum shares
        std::vector<Share> recovery_shares(shares.begin(), shares.begin() + test_case.threshold);
        std::string recovered = crypto::ShamirSecretSharing::recover_secret(recovery_shares);
        vector["recovery_successful"] = (recovered == test_case.secret_hex);
        
        shamir_vectors.push_back(vector);
    }
    test_vectors["shamir_secret_sharing_vectors"] = shamir_vectors;
    
    // Cross-language compatibility test cases
    std::cout << "🌐 Generating cross-language compatibility test cases..." << std::endl;
    json compatibility;
    
    // Standard test inputs for cross-language verification
    std::string std_uid = "test-user";
    std::string std_did = "test-device";
    std::string std_bid = "backup-001";
    std::string std_pin = "1234";
    
    Bytes std_uid_bytes = utils::string_to_bytes(std_uid);
    Bytes std_did_bytes = utils::string_to_bytes(std_did);
    Bytes std_bid_bytes = utils::string_to_bytes(std_bid);
    Bytes std_pin_bytes = utils::string_to_bytes(std_pin);
    
    Point4D std_point = crypto::Ed25519::hash_to_point(std_uid_bytes, std_did_bytes, std_bid_bytes, std_pin_bytes);
    Bytes std_compressed = crypto::Ed25519::compress(std_point);
    
    compatibility["standard_test_case"]["inputs"]["uid"] = std_uid;
    compatibility["standard_test_case"]["inputs"]["did"] = std_did;
    compatibility["standard_test_case"]["inputs"]["bid"] = std_bid;
    compatibility["standard_test_case"]["inputs"]["pin"] = std_pin;
    compatibility["standard_test_case"]["expected_point"] = point_to_json(std_point);
    compatibility["standard_test_case"]["expected_compressed_hex"] = bytes_to_hex_string(std_compressed);
    
    // SHA256 reference
    std::string reference_message = "OpenADP cross-language test";
    Bytes reference_bytes = utils::string_to_bytes(reference_message);
    Bytes reference_hash = crypto::sha256_hash(reference_bytes);
    
    compatibility["sha256_reference"]["input"] = reference_message;
    compatibility["sha256_reference"]["expected"] = bytes_to_hex_string(reference_hash);
    
    test_vectors["cross_language_compatibility"] = compatibility;
    
    // Write to file
    std::cout << "💾 Writing test vectors to file..." << std::endl;
    std::ofstream file("openadp_test_vectors.json");
    file << test_vectors.dump(2);
    file.close();
    
    std::cout << "✅ Test vectors generated successfully!" << std::endl;
    std::cout << "📄 Output file: openadp_test_vectors.json" << std::endl;
    
    // Print summary
    std::cout << "\n📊 Test Vector Summary:" << std::endl;
    std::cout << "  • SHA256 vectors: " << sha256_vectors.size() << std::endl;
    std::cout << "  • Prefixed vectors: " << prefixed_vectors.size() << std::endl;
    std::cout << "  • Hash-to-point vectors: " << hash_to_point_vectors.size() << std::endl;
    std::cout << "  • HKDF vectors: " << hkdf_vectors.size() << std::endl;
    std::cout << "  • AES-GCM vectors: " << aes_gcm_vectors.size() << std::endl;
    std::cout << "  • Shamir vectors: " << shamir_vectors.size() << std::endl;
    std::cout << "  • Cross-language compatibility cases included" << std::endl;
    
    return 0;
} 