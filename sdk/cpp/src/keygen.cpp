#include "openadp/keygen.hpp"
#include "openadp/types.hpp"
#include "openadp/client.hpp"
#include "openadp/crypto.hpp"
#include "openadp/utils.hpp"
#include "openadp/debug.hpp"
#include <chrono>
#include <algorithm>

namespace openadp {
namespace keygen {

std::string generate_random_scalar() {
    if (debug::is_debug_mode_enabled()) {
        // In debug mode, use large deterministic secret
        return debug::get_deterministic_main_secret();
    } else {
        // In normal mode, use cryptographically secure random
        return utils::random_hex(32); // 256-bit scalar
    }
}

AuthCodes generate_auth_codes(const std::string& base_auth_code, const std::vector<ServerInfo>& server_infos) {
    AuthCodes auth_codes;
    auth_codes.base_auth_code = base_auth_code;
    
    // Generate server-specific auth codes using SHA256
    for (const auto& server_info : server_infos) {
        std::string combined = base_auth_code + ":" + server_info.url;
        Bytes combined_bytes = utils::string_to_bytes(combined);
        Bytes hash = crypto::sha256_hash(combined_bytes);
        std::string server_code = utils::hex_encode(hash);
        auth_codes.server_auth_codes[server_info.url] = server_code;
    }
    
    return auth_codes;
}

GenerateEncryptionKeyResult generate_encryption_key(
    const Identity& identity,
    const std::string& password,
    int max_guesses,
    int64_t expiration,
    const std::vector<ServerInfo>& server_infos
) {
    try {
        // Input validation
        if (identity.uid.empty()) {
            return GenerateEncryptionKeyResult::error("User ID cannot be empty");
        }
        if (identity.did.empty()) {
            return GenerateEncryptionKeyResult::error("Device ID cannot be empty");
        }
        if (identity.bid.empty()) {
            return GenerateEncryptionKeyResult::error("Backup ID cannot be empty");
        }
        
        if (password.empty()) {
            return GenerateEncryptionKeyResult::error("Password cannot be empty");
        }
        
        if (max_guesses <= 0) {
            return GenerateEncryptionKeyResult::error("Max guesses must be positive");
        }
        if (max_guesses > 100000) {
            return GenerateEncryptionKeyResult::error("Max guesses too large");
        }
        
        // Check expiration (if provided)
        if (expiration > 0) {
            auto now = std::chrono::system_clock::now();
            auto current_time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            if (expiration < current_time) {
                return GenerateEncryptionKeyResult::error("Expiration time is in the past");
            }
        }
        
        // Check if we have enough servers
        if (server_infos.empty()) {
            return GenerateEncryptionKeyResult::error("No servers available");
        }
        
        // Validate server URLs
        for (const auto& server_info : server_infos) {
            if (server_info.url.empty()) {
                return GenerateEncryptionKeyResult::error("Server URL cannot be empty");
            }
            if (server_info.url.find("http://") != 0 && server_info.url.find("https://") != 0) {
                return GenerateEncryptionKeyResult::error("Invalid server URL format: " + server_info.url);
            }
        }
        
        // Calculate threshold (majority: n/2 + 1, but at least 1)
        int threshold = std::max(1, static_cast<int>(server_infos.size()) / 2 + 1);
        
        // For single server, we need that server to succeed
        if (server_infos.size() == 1) {
            threshold = 1;
        }
        
        // Generate random scalar b
        std::string b_hex = generate_random_scalar();
        
        // Generate base auth code
        std::string base_auth_code = utils::random_hex(16);
        
        // Generate server-specific auth codes
        AuthCodes auth_codes = generate_auth_codes(base_auth_code, server_infos);
        
        // Convert password to bytes
        Bytes password_bytes = utils::string_to_bytes(password);
        Bytes uid_bytes = utils::string_to_bytes(identity.uid);
        Bytes did_bytes = utils::string_to_bytes(identity.did);
        Bytes bid_bytes = utils::string_to_bytes(identity.bid);
        
        // Compute H(uid, did, bid, pin)
        Point4D H = crypto::Ed25519::hash_to_point(uid_bytes, did_bytes, bid_bytes, password_bytes);
        
        // Compute b * H
        Point4D bH = crypto::Ed25519::scalar_mult(b_hex, H);
        
        // Compress to get x coordinate
        Bytes bH_compressed = crypto::Ed25519::compress(bH);
        std::string x_hex = utils::hex_encode(bH_compressed);
        
        // Set expiration if not provided
        if (expiration == 0) {
            auto now = std::chrono::system_clock::now();
            auto future = now + std::chrono::hours(24 * 365); // 1 year
            expiration = std::chrono::duration_cast<std::chrono::seconds>(future.time_since_epoch()).count();
        }
        
        // Register with servers
        std::vector<ServerInfo> successful_servers;
        
        for (const auto& server_info : server_infos) {
            try {
                client::EncryptedOpenADPClient client(server_info.url, server_info.public_key);
                
                client::RegisterSecretRequest request(identity, password, max_guesses, expiration, b_hex);
                nlohmann::json response = client.register_secret(request);
                
                if (response.contains("success") && response["success"].get<bool>()) {
                    successful_servers.push_back(server_info);
                }
            } catch (const std::exception& e) {
                // Continue with other servers
                continue;
            }
        }
        
        if (successful_servers.size() < static_cast<size_t>(threshold)) {
            return GenerateEncryptionKeyResult::error(
                "Not enough servers responded successfully. Got " + 
                std::to_string(successful_servers.size()) + ", need " + std::to_string(threshold)
            );
        }
        
        // Derive encryption key from x coordinate
        Point4D point_for_key = crypto::Ed25519::decompress(crypto::hex_to_bytes(x_hex));
        Bytes encryption_key = crypto::derive_encryption_key(point_for_key);
        
        return GenerateEncryptionKeyResult::success(encryption_key, auth_codes, successful_servers, threshold);
        
    } catch (const std::exception& e) {
        return GenerateEncryptionKeyResult::error(std::string("Key generation failed: ") + e.what());
    }
}

RecoverEncryptionKeyResult recover_encryption_key(
    const Identity& identity,
    const std::string& password,
    const AuthCodes& auth_codes,
    const std::vector<ServerInfo>& server_infos
) {
    try {
        if (server_infos.empty()) {
            return RecoverEncryptionKeyResult::error("No servers available");
        }
        
        // Convert password to bytes
        Bytes password_bytes = utils::string_to_bytes(password);
        Bytes uid_bytes = utils::string_to_bytes(identity.uid);
        Bytes did_bytes = utils::string_to_bytes(identity.did);
        Bytes bid_bytes = utils::string_to_bytes(identity.bid);
        
        // Compute H(uid, did, bid, pin)
        Point4D H = crypto::Ed25519::hash_to_point(uid_bytes, did_bytes, bid_bytes, password_bytes);
        
        // Recover shares from servers
        std::vector<Share> shares;
        int remaining_guesses = 0;
        
        for (const auto& server_info : server_infos) {
            try {
                // Find the auth code for this server
                auto auth_it = auth_codes.server_auth_codes.find(server_info.url);
                if (auth_it == auth_codes.server_auth_codes.end()) {
                    continue; // Skip servers without auth codes
                }
                
                client::EncryptedOpenADPClient client(server_info.url, server_info.public_key);
                
                // First, get the guess number by listing backups
                nlohmann::json backups = client.list_backups(identity);
                int guess_num = 1;
                if (backups.contains("guess_num")) {
                    guess_num = backups["guess_num"].get<int>();
                }
                
                // Create a fresh client for the recovery request
                client::EncryptedOpenADPClient fresh_client(server_info.url, server_info.public_key);
                
                client::RecoverSecretRequest request(identity, password, guess_num);
                nlohmann::json response = fresh_client.recover_secret(request);
                
                if (response.contains("success") && response["success"].get<bool>()) {
                    if (response.contains("b") && response.contains("remaining_guesses")) {
                        std::string b_hex = response["b"].get<std::string>();
                        remaining_guesses = response["remaining_guesses"].get<int>();
                        
                        // Create share (server index as x, b as y)
                        int server_index = static_cast<int>(shares.size() + 1);
                        shares.emplace_back(server_index, b_hex);
                    }
                }
            } catch (const std::exception& e) {
                // Continue with other servers
                continue;
            }
        }
        
        if (shares.empty()) {
            return RecoverEncryptionKeyResult::error("No valid shares recovered");
        }
        
        // For now, assume we only need one share (1-of-N threshold)
        // In a full implementation, this would use Shamir secret sharing
        std::string b_hex = shares[0].y;
        
        // Compute b * H
        Point4D bH = crypto::Ed25519::scalar_mult(b_hex, H);
        
        // Derive encryption key
        Bytes encryption_key = crypto::derive_encryption_key(bH);
        
        return RecoverEncryptionKeyResult::success(encryption_key, remaining_guesses);
        
    } catch (const std::exception& e) {
        return RecoverEncryptionKeyResult::error(std::string("Key recovery failed: ") + e.what());
    }
}

} // namespace keygen
} // namespace openadp 