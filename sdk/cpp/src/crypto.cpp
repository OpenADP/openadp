#include "openadp/crypto.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <cstring>
#include <algorithm>
#include <numeric>

namespace openadp {
namespace crypto {

// Helper function to convert hex string to BIGNUM
BIGNUM* hex_to_bn(const std::string& hex) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

// Helper function to convert BIGNUM to hex string
std::string bn_to_hex(const BIGNUM* bn) {
    char* hex_str = BN_bn2hex(bn);
    std::string result(hex_str);
    OPENSSL_free(hex_str);
    return result;
}

// Hash function
Bytes sha256_hash(const Bytes& data) {
    Bytes result(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), result.data());
    return result;
}

// Prefixed function (length prefix + data)
Bytes prefixed(const Bytes& data) {
    Bytes result;
    uint16_t length = static_cast<uint16_t>(data.size());
    
    // Little-endian encoding (16-bit)
    result.push_back(length & 0xFF);
    result.push_back((length >> 8) & 0xFF);
    
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

std::string bytes_to_hex(const Bytes& data) {
    return utils::hex_encode(data);
}

Bytes hex_to_bytes(const std::string& hex) {
    return utils::hex_decode(hex);
}

// Ed25519 implementation
Point4D Ed25519::hash_to_point(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin) {
    // Concatenate all inputs with length prefixes
    Bytes prefixed_uid = prefixed(uid);
    Bytes prefixed_did = prefixed(did);
    Bytes prefixed_bid = prefixed(bid);
    
    Bytes data;
    data.insert(data.end(), prefixed_uid.begin(), prefixed_uid.end());
    data.insert(data.end(), prefixed_did.begin(), prefixed_did.end());
    data.insert(data.end(), prefixed_bid.begin(), prefixed_bid.end());
    data.insert(data.end(), pin.begin(), pin.end());
    
    // Hash and convert to point
    Bytes hash_bytes = sha256_hash(data);
    
    // Convert hash to big integer (little-endian)
    BIGNUM* y_base = BN_new();
    BN_zero(y_base);
    
    for (size_t i = 0; i < hash_bytes.size(); ++i) {
        BIGNUM* byte_bn = BN_new();
        BN_set_word(byte_bn, hash_bytes[i]);
        
        BIGNUM* shift_bn = BN_new();
        BN_set_word(shift_bn, 1);
        BN_lshift(shift_bn, shift_bn, i * 8);
        
        BN_mul(byte_bn, byte_bn, shift_bn, BN_CTX_new());
        BN_add(y_base, y_base, byte_bn);
        
        BN_free(byte_bn);
        BN_free(shift_bn);
    }
    
    // Reduce modulo curve order
    BIGNUM* curve_order = hex_to_bn("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
    BN_mod(y_base, y_base, curve_order, BN_CTX_new());
    
    // Create point coordinates (simplified - this would need proper Ed25519 point construction)
    std::string y_hex = bn_to_hex(y_base);
    
    BN_free(y_base);
    BN_free(curve_order);
    
    // For now, return a simplified point (this needs proper Ed25519 implementation)
    return Point4D("0", y_hex, "1", "0");
}

Point4D Ed25519::scalar_mult(const std::string& scalar_hex, const Point4D& point) {
    // This is a simplified implementation - would need proper Ed25519 scalar multiplication
    BIGNUM* scalar = hex_to_bn(scalar_hex);
    BIGNUM* y = hex_to_bn(point.y);
    
    // Simplified multiplication (not cryptographically correct)
    BN_mul(y, y, scalar, BN_CTX_new());
    
    std::string result_y = bn_to_hex(y);
    
    BN_free(scalar);
    BN_free(y);
    
    return Point4D(point.x, result_y, point.z, point.t);
}

Point4D Ed25519::point_add(const Point4D& p1, const Point4D& p2) {
    // Simplified point addition (not cryptographically correct)
    BIGNUM* y1 = hex_to_bn(p1.y);
    BIGNUM* y2 = hex_to_bn(p2.y);
    
    BN_add(y1, y1, y2);
    
    std::string result_y = bn_to_hex(y1);
    
    BN_free(y1);
    BN_free(y2);
    
    return Point4D("0", result_y, "1", "0");
}

Bytes Ed25519::compress(const Point4D& point) {
    // Convert point to compressed form
    Bytes result = hex_to_bytes(point.y);
    if (result.size() < 32) {
        result.resize(32, 0);
    }
    return result;
}

Point4D Ed25519::decompress(const Bytes& data) {
    std::string y_hex = bytes_to_hex(data);
    return Point4D("0", y_hex, "1", "0");
}

Point4D Ed25519::expand(const Point2D& point) {
    return Point4D(point.x, point.y, "1", "0");
}

Point2D Ed25519::unexpand(const Point4D& point) {
    return Point2D(point.x, point.y);
}

bool Ed25519::is_valid_point(const Point4D& point) {
    // Simplified validation
    return !point.y.empty();
}

Point4D Ed25519::point_mul8(const Point4D& point) {
    return scalar_mult("8", point);
}

// Shamir Secret Sharing
std::vector<Share> ShamirSecretSharing::split_secret(const std::string& secret_hex, int threshold, int num_shares) {
    BIGNUM* secret = hex_to_bn(secret_hex);
    BIGNUM* prime = hex_to_bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); // secp256k1 prime
    
    // Generate random coefficients
    std::vector<BIGNUM*> coefficients;
    coefficients.push_back(BN_dup(secret)); // a0 = secret
    
    for (int i = 1; i < threshold; i++) {
        BIGNUM* coeff = BN_new();
        BN_rand_range(coeff, prime);
        coefficients.push_back(coeff);
    }
    
    // Generate shares
    std::vector<Share> shares;
    for (int x = 1; x <= num_shares; x++) {
        BIGNUM* y = BN_new();
        BN_zero(y);
        
        BIGNUM* x_power = BN_new();
        BN_one(x_power);
        
        for (int i = 0; i < threshold; i++) {
            BIGNUM* term = BN_new();
            BN_mul(term, coefficients[i], x_power, BN_CTX_new());
            BN_add(y, y, term);
            
            BN_mul_word(x_power, x);
            BN_free(term);
        }
        
        BN_mod(y, y, prime, BN_CTX_new());
        shares.emplace_back(x, bn_to_hex(y));
        
        BN_free(y);
        BN_free(x_power);
    }
    
    // Cleanup
    for (BIGNUM* coeff : coefficients) {
        BN_free(coeff);
    }
    BN_free(secret);
    BN_free(prime);
    
    return shares;
}

std::string ShamirSecretSharing::recover_secret(const std::vector<Share>& shares) {
    if (shares.empty()) {
        throw OpenADPError("No shares provided");
    }
    
    BIGNUM* prime = hex_to_bn("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    BIGNUM* result = BN_new();
    BN_zero(result);
    
    // Lagrange interpolation
    for (size_t i = 0; i < shares.size(); i++) {
        BIGNUM* numerator = BN_new();
        BIGNUM* denominator = BN_new();
        BN_one(numerator);
        BN_one(denominator);
        
        for (size_t j = 0; j < shares.size(); j++) {
            if (i != j) {
                // Numerator: multiply by shares[j].x
                BN_mul_word(numerator, shares[j].x);
                
                // Denominator: multiply by (shares[j].x - shares[i].x)
                BIGNUM* diff = BN_new();
                if (shares[j].x >= shares[i].x) {
                    BN_set_word(diff, shares[j].x - shares[i].x);
                } else {
                    // Handle negative difference: compute prime - (shares[i].x - shares[j].x)
                    BN_set_word(diff, shares[i].x - shares[j].x);
                    BIGNUM* temp = BN_dup(prime);
                    BN_sub(temp, temp, diff);
                    BN_copy(diff, temp);
                    BN_free(temp);
                }
                
                BN_mul(denominator, denominator, diff, BN_CTX_new());
                BN_free(diff);
            }
        }
        
        // Modular inverse
        BIGNUM* inv = BN_new();
        BN_mod_inverse(inv, denominator, prime, BN_CTX_new());
        
        BIGNUM* lagrange = BN_new();
        BN_mul(lagrange, numerator, inv, BN_CTX_new());
        BN_mod(lagrange, lagrange, prime, BN_CTX_new());
        
        BIGNUM* y = hex_to_bn(shares[i].y);
        BN_mul(lagrange, lagrange, y, BN_CTX_new());
        BN_add(result, result, lagrange);
        
        BN_free(numerator);
        BN_free(denominator);
        BN_free(inv);
        BN_free(lagrange);
        BN_free(y);
    }
    
    BN_mod(result, result, prime, BN_CTX_new());
    std::string secret_hex = bn_to_hex(result);
    
    BN_free(result);
    BN_free(prime);
    
    return secret_hex;
}

// Point Secret Sharing (simplified)
std::vector<PointShare> PointSecretSharing::split_point(const Point2D& point, int threshold, int num_shares) {
    auto x_shares = ShamirSecretSharing::split_secret(point.x, threshold, num_shares);
    auto y_shares = ShamirSecretSharing::split_secret(point.y, threshold, num_shares);
    
    std::vector<PointShare> point_shares;
    for (int i = 0; i < num_shares; i++) {
        Point2D share_point(x_shares[i].y, y_shares[i].y);
        point_shares.emplace_back(x_shares[i].x, share_point);
    }
    
    return point_shares;
}

Point2D PointSecretSharing::recover_point(const std::vector<PointShare>& shares) {
    std::vector<Share> x_shares, y_shares;
    
    for (const auto& point_share : shares) {
        x_shares.emplace_back(point_share.x, point_share.point.x);
        y_shares.emplace_back(point_share.x, point_share.point.y);
    }
    
    std::string x = ShamirSecretSharing::recover_secret(x_shares);
    std::string y = ShamirSecretSharing::recover_secret(y_shares);
    
    return Point2D(x, y);
}

// Key derivation
Bytes derive_encryption_key(const Point4D& point) {
    Bytes point_bytes = Ed25519::compress(point);
    return sha256_hash(point_bytes);
}

// AES-GCM encryption
AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& associated_data) {
    if (key.size() != 32) {
        throw OpenADPError("AES key must be 32 bytes");
    }
    
    // Generate random nonce
    Bytes nonce = utils::random_bytes(12);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenADPError("Failed to create cipher context");
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to initialize AES-GCM");
    }
    
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set nonce length");
    }
    
    // Set key and nonce
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set key and nonce");
    }
    
    // Set associated data
    int len;
    if (!associated_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenADPError("Failed to set associated data");
        }
    }
    
    // Encrypt
    Bytes ciphertext(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Encryption failed");
    }
    ciphertext.resize(len);
    
    // Finalize
    Bytes final_block(16);
    if (EVP_EncryptFinal_ex(ctx, final_block.data(), &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Encryption finalization failed");
    }
    
    if (len > 0) {
        ciphertext.insert(ciphertext.end(), final_block.begin(), final_block.begin() + len);
    }
    
    // Get tag
    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    return AESGCMResult{ciphertext, tag, nonce};
}

AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key) {
    return aes_gcm_encrypt(plaintext, key, Bytes{});
}

Bytes aes_gcm_decrypt(const Bytes& ciphertext, const Bytes& tag, const Bytes& nonce, 
                     const Bytes& key, const Bytes& associated_data) {
    if (key.size() != 32) {
        throw OpenADPError("AES key must be 32 bytes");
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenADPError("Failed to create cipher context");
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to initialize AES-GCM");
    }
    
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set nonce length");
    }
    
    // Set key and nonce
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set key and nonce");
    }
    
    // Set associated data
    int len;
    if (!associated_data.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenADPError("Failed to set associated data");
        }
    }
    
    // Decrypt
    Bytes plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Decryption failed");
    }
    plaintext.resize(len);
    
    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set authentication tag");
    }
    
    // Finalize
    Bytes final_block(16);
    int ret = EVP_DecryptFinal_ex(ctx, final_block.data(), &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        throw OpenADPError("Authentication tag verification failed");
    }
    
    if (len > 0) {
        plaintext.insert(plaintext.end(), final_block.begin(), final_block.begin() + len);
    }
    
    return plaintext;
}

Bytes aes_gcm_decrypt(const Bytes& ciphertext, const Bytes& tag, const Bytes& nonce, 
                     const Bytes& key) {
    return aes_gcm_decrypt(ciphertext, tag, nonce, key, Bytes{});
}

// HKDF key derivation
Bytes hkdf_derive(const Bytes& input_key, const Bytes& salt, const Bytes& info, size_t output_length) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        throw OpenADPError("Failed to create HKDF context");
    }
    
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to initialize HKDF");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF hash function");
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, input_key.data(), input_key.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF input key");
    }
    
    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw OpenADPError("Failed to set HKDF salt");
        }
    }
    
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), info.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw OpenADPError("Failed to set HKDF info");
        }
    }
    
    Bytes output(output_length);
    size_t out_len = output_length;
    
    if (EVP_PKEY_derive(ctx, output.data(), &out_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("HKDF derivation failed");
    }
    
    EVP_PKEY_CTX_free(ctx);
    output.resize(out_len);
    
    return output;
}

} // namespace crypto
} // namespace openadp 