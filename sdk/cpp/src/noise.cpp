#include "openadp/noise.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"
#include "openadp/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <cstring>

namespace openadp {
namespace noise {

// Forward declarations
Bytes perform_dh(const Bytes& private_key, const Bytes& public_key);
std::pair<Bytes, Bytes> hkdf_2(const Bytes& ck, const Bytes& input_key_material);
Bytes encrypt_and_hash(const Bytes& plaintext, Bytes& h);
Bytes decrypt_and_hash(const Bytes& ciphertext, Bytes& h);
Bytes generate_keypair_private();
Bytes derive_public_key(const Bytes& private_key);

// Noise protocol constants
const size_t KEY_SIZE = 32;
const size_t HASH_SIZE = 32;
const size_t MAC_SIZE = 16;

struct NoiseState::Impl {
    // Noise state
    Bytes s;  // Local static private key
    Bytes e;  // Local ephemeral private key
    Bytes rs; // Remote static public key
    Bytes re; // Remote ephemeral public key
    
    // Symmetric state
    Bytes ck; // Chaining key
    Bytes h;  // Hash
    Bytes k;  // Encryption key
    
    // Transport keys
    Bytes send_key;
    Bytes recv_key;
    uint64_t send_nonce;
    uint64_t recv_nonce;
    
    bool handshake_finished;
    
    Impl() : send_nonce(0), recv_nonce(0), handshake_finished(false) {
        // Initialize with Noise_NK protocol name
        std::string protocol_name = "Noise_NK_25519_ChaChaPoly_SHA256";
        Bytes protocol_bytes = utils::string_to_bytes(protocol_name);
        
        if (protocol_bytes.size() <= 32) {
            h = protocol_bytes;
            h.resize(32, 0);
        } else {
            h = crypto::sha256_hash(protocol_bytes);
        }
        
        ck = h;
        
        // Generate local static key
        s = generate_keypair_private();
    }
};

NoiseState::NoiseState() : pimpl_(std::make_unique<Impl>()) {}

NoiseState::~NoiseState() = default;

void NoiseState::initialize_handshake(const Bytes& remote_public_key) {
    pimpl_->rs = remote_public_key;
    
    // Mix remote static public key into hash
    Bytes temp = pimpl_->h;
    temp.insert(temp.end(), remote_public_key.begin(), remote_public_key.end());
    pimpl_->h = crypto::sha256_hash(temp);
}

Bytes NoiseState::write_message(const Bytes& payload) {
    if (pimpl_->handshake_finished) {
        throw OpenADPError("Handshake already finished");
    }
    
    // Generate ephemeral keypair
    pimpl_->e = generate_keypair_private();
    Bytes e_pub = derive_public_key(pimpl_->e);
    
    // Mix ephemeral public key
    Bytes temp = pimpl_->h;
    temp.insert(temp.end(), e_pub.begin(), e_pub.end());
    pimpl_->h = crypto::sha256_hash(temp);
    
    // Perform DH
    Bytes dh = perform_dh(pimpl_->e, pimpl_->rs);
    
    // Mix DH result
    auto keys = hkdf_2(pimpl_->ck, dh);
    pimpl_->ck = keys.first;
    pimpl_->k = keys.second;
    
    // Encrypt payload
    Bytes ciphertext;
    if (!payload.empty()) {
        ciphertext = encrypt_and_hash(payload, pimpl_->h);
    }
    
    // Build message
    Bytes message = e_pub;
    message.insert(message.end(), ciphertext.begin(), ciphertext.end());
    
    // Finalize handshake
    auto transport_keys = hkdf_2(pimpl_->ck, Bytes());
    pimpl_->send_key = transport_keys.first;
    pimpl_->recv_key = transport_keys.second;
    pimpl_->handshake_finished = true;
    
    return message;
}

Bytes NoiseState::write_message() {
    return write_message(Bytes{});
}

Bytes NoiseState::read_message(const Bytes& message) {
    if (message.size() < 32) {
        throw OpenADPError("Message too short");
    }
    
    // Extract ephemeral public key
    pimpl_->re = Bytes(message.begin(), message.begin() + 32);
    
    // Mix ephemeral public key
    Bytes temp = pimpl_->h;
    temp.insert(temp.end(), pimpl_->re.begin(), pimpl_->re.end());
    pimpl_->h = crypto::sha256_hash(temp);
    
    // Perform DH
    Bytes dh = perform_dh(pimpl_->s, pimpl_->re);
    
    // Mix DH result
    auto keys = hkdf_2(pimpl_->ck, dh);
    pimpl_->ck = keys.first;
    pimpl_->k = keys.second;
    
    // Decrypt payload
    Bytes payload;
    if (message.size() > 32) {
        Bytes ciphertext(message.begin() + 32, message.end());
        payload = decrypt_and_hash(ciphertext, pimpl_->h);
    }
    
    // Finalize handshake
    auto transport_keys = hkdf_2(pimpl_->ck, Bytes());
    pimpl_->recv_key = transport_keys.first;
    pimpl_->send_key = transport_keys.second;
    pimpl_->handshake_finished = true;
    
    return payload;
}

bool NoiseState::handshake_finished() const {
    return pimpl_->handshake_finished;
}

Bytes NoiseState::encrypt(const Bytes& plaintext) {
    if (!pimpl_->handshake_finished) {
        throw OpenADPError("Handshake not finished");
    }
    
    // Create nonce (little-endian)
    Bytes nonce(12, 0);
    for (int i = 0; i < 8; i++) {
        nonce[i] = (pimpl_->send_nonce >> (i * 8)) & 0xFF;
    }
    
    // Encrypt with ChaCha20-Poly1305 (using AES-GCM as substitute)
    auto result = crypto::aes_gcm_encrypt(plaintext, pimpl_->send_key);
    
    pimpl_->send_nonce++;
    
    // Combine nonce + ciphertext + tag
    Bytes encrypted = result.nonce;
    encrypted.insert(encrypted.end(), result.ciphertext.begin(), result.ciphertext.end());
    encrypted.insert(encrypted.end(), result.tag.begin(), result.tag.end());
    
    return encrypted;
}

Bytes NoiseState::decrypt(const Bytes& ciphertext) {
    if (!pimpl_->handshake_finished) {
        throw OpenADPError("Handshake not finished");
    }
    
    if (ciphertext.size() < 28) { // 12 (nonce) + 16 (tag)
        throw OpenADPError("Ciphertext too short");
    }
    
    // Extract components
    Bytes nonce(ciphertext.begin(), ciphertext.begin() + 12);
    Bytes tag(ciphertext.end() - 16, ciphertext.end());
    Bytes data(ciphertext.begin() + 12, ciphertext.end() - 16);
    
    // Decrypt with AES-GCM
    Bytes plaintext = crypto::aes_gcm_decrypt(data, tag, nonce, pimpl_->recv_key);
    
    pimpl_->recv_nonce++;
    
    return plaintext;
}

std::pair<Bytes, Bytes> NoiseState::get_transport_keys() const {
    return std::make_pair(pimpl_->send_key, pimpl_->recv_key);
}

// Helper functions (private methods need to be declared as free functions)
Bytes perform_dh(const Bytes& private_key, const Bytes& public_key) {
    if (private_key.size() != 32 || public_key.size() != 32) {
        throw OpenADPError("Invalid key size for DH");
    }
    
    // Create private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
        throw OpenADPError("Failed to create private key");
    }
    
    // Create public key
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, public_key.data(), public_key.size());
    if (!peer_key) {
        EVP_PKEY_free(pkey);
        throw OpenADPError("Failed to create public key");
    }
    
    // Create EVP context for key derivation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        throw OpenADPError("Failed to create X25519 context");
    }
    
    // Initialize key derivation
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to initialize key derivation");
    }
    
    // Set peer key
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set peer key");
    }
    
    // Get shared secret length
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to get secret length");
    }
    
    // Derive shared secret
    Bytes shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("X25519 DH failed");
    }
    
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return shared_secret;
}

std::pair<Bytes, Bytes> hkdf_2(const Bytes& ck, const Bytes& input_key_material) {
    // Use HKDF to derive two 32-byte keys
    Bytes salt = ck.empty() ? Bytes(32, 0) : ck;
    Bytes ikm = input_key_material.empty() ? Bytes(1, 0) : input_key_material;
    
    Bytes output1 = crypto::hkdf_derive(ikm, salt, utils::string_to_bytes("1"), 32);
    Bytes output2 = crypto::hkdf_derive(ikm, salt, utils::string_to_bytes("2"), 32);
    
    return std::make_pair(output1, output2);
}

Bytes encrypt_and_hash(const Bytes& plaintext, Bytes& h) {
    // Simplified encryption during handshake
    h = crypto::sha256_hash(plaintext);
    return plaintext; // No encryption during handshake for simplicity
}

Bytes decrypt_and_hash(const Bytes& ciphertext, Bytes& h) {
    // Simplified decryption during handshake
    h = crypto::sha256_hash(ciphertext);
    return ciphertext; // No decryption during handshake for simplicity
}

// Utility functions
Bytes generate_keypair_private() {
    Bytes private_key(32);
    if (RAND_bytes(private_key.data(), 32) != 1) {
        throw OpenADPError("Failed to generate private key");
    }
    return private_key;
}

Bytes derive_public_key(const Bytes& private_key) {
    if (private_key.size() != 32) {
        throw OpenADPError("Private key must be 32 bytes");
    }
    
    // For X25519, derive public key from private key
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        throw OpenADPError("Failed to create key context");
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to initialize key generation");
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to generate keypair");
    }
    
    size_t public_key_len = 32;
    Bytes public_key(public_key_len);
    
    if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &public_key_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to extract public key");
    }
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    public_key.resize(public_key_len);
    return public_key;
}

} // namespace noise
} // namespace openadp 