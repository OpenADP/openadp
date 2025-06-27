#include "openadp/noise.hpp"
#include "openadp/crypto.hpp"
#include "openadp/utils.hpp"
#include "openadp/debug.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <nlohmann/json.hpp>
#include <getopt.h>

using json = nlohmann::json;
using namespace openadp;

bool server_running = true;

void signal_handler(int signal) {
    std::cout << "\n🛑 Shutting down server..." << std::endl;
    server_running = false;
}

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

void handle_client(int client_fd, const std::string& client_addr, const Bytes& server_private_key) {
    std::cout << "📞 New connection from " << client_addr << std::endl;
    std::cout << "🔒 Starting Noise-NK handshake with " << client_addr << std::endl;
    
    try {
        // Initialize Noise-NK server
        noise::NoiseState server;
        server.initialize_responder(server_private_key);
        
        // Receive first handshake message from client
        Bytes client_message = receive_message(client_fd);
        if (client_message.empty()) {
            std::cout << "❌ Failed to receive handshake message 1 from " << client_addr << std::endl;
            close(client_fd);
            return;
        }
        
        std::cout << "📨 Received handshake message 1: " << client_message.size() << " bytes" << std::endl;
        std::cout << "🔍 Raw message 1 hex: " << crypto::bytes_to_hex(client_message) << std::endl;
        
        // Process client handshake message
        Bytes client_payload = server.read_message(client_message);
        std::cout << "📝 Client payload 1: " << client_payload.size() << " bytes" << std::endl;
        
        // Send second handshake message to client
        Bytes server_message = server.write_message();
        std::cout << "📤 Sent handshake message 2: " << server_message.size() << " bytes" << std::endl;
        
        if (!send_message(client_fd, server_message)) {
            std::cout << "❌ Failed to send handshake message 2 to " << client_addr << std::endl;
            close(client_fd);
            return;
        }
        
        if (!server.handshake_finished()) {
            std::cout << "❌ Handshake not completed with " << client_addr << std::endl;
            close(client_fd);
            return;
        }
        
        std::cout << "🔑 C++ final handshake hash: " << crypto::bytes_to_hex(server.get_handshake_hash()) << std::endl;
        std::cout << "✅ Noise-NK handshake completed with " << client_addr << std::endl;
        std::cout << "🔐 Secure channel established with " << client_addr << std::endl;
        
        // Handle secure communication
        while (server_running) {
            Bytes encrypted_data = receive_message(client_fd);
            if (encrypted_data.empty()) {
                std::cout << "📡 Client " << client_addr << " disconnected" << std::endl;
                break;
            }
            
            try {
                // Decrypt message
                Bytes plaintext = server.decrypt(encrypted_data);
                std::string message = utils::bytes_to_string(plaintext);
                std::cout << "📨 Received from " << client_addr << ": " << message << std::endl;
                
                // Send echo response
                std::string response = "Echo: " + message + " (from C++ server)";
                Bytes response_bytes = utils::string_to_bytes(response);
                Bytes encrypted_response = server.encrypt(response_bytes);
                
                if (!send_message(client_fd, encrypted_response)) {
                    std::cout << "❌ Failed to send response to " << client_addr << std::endl;
                    break;
                }
                
                std::cout << "📤 Sent response to " << client_addr << ": " << response << std::endl;
                
            } catch (const OpenADPError& e) {
                std::cout << "❌ Error processing encrypted message from " << client_addr << ": " << e.what() << std::endl;
                break;
            }
        }
        
    } catch (const OpenADPError& e) {
        std::cout << "❌ Failed to process handshake message 1: " << e.what() << std::endl;
        std::cout << "🔍 This might be due to payload encryption mismatch" << std::endl;
    }
    
    close(client_fd);
    std::cout << "🔌 Disconnected from " << client_addr << std::endl;
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Simple Noise-NK server for testing OpenADP clients.\n"
              << "\n"
              << "Options:\n"
              << "  --port <num>          Port to listen on (default: 8080)\n"
              << "  --debug               Enable debug mode (deterministic operations)\n"
              << "  --help                Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << "\n"
              << "  " << program_name << " --port 9090\n";
}

int main(int argc, char* argv[]) {
    int port = 8080;
    bool debug_mode = false;
    
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "p:dh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'p':
                port = std::stoi(optarg);
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                break;
        }
    }
    
    // Set debug mode if requested
    if (debug_mode) {
        debug::set_debug(true);
    }
    
    std::cout << "🔐 Noise-NK C++ TCP Server" << std::endl;
    std::cout << "===========================" << std::endl;
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    try {
        // Generate server keys
        Bytes server_private_key = noise::generate_keypair_private();
        Bytes server_public_key = noise::derive_public_key(server_private_key);
        
        std::string server_public_hex = crypto::bytes_to_hex(server_public_key);
        std::cout << "🔐 Server static public key: " << server_public_hex << std::endl;
        std::cout << "🔐 Clients should use this key to connect" << std::endl;
        
        // Save server info to JSON file
        json server_info = {
            {"host", "localhost"},
            {"port", port},
            {"public_key", server_public_hex},
            {"protocol", "Noise_NK_25519_AESGCM_SHA256"}
        };
        
        std::ofstream server_info_file("server_info.json");
        server_info_file << server_info.dump(2) << std::endl;
        server_info_file.close();
        
        std::cout << "💾 Server info saved to server_info.json" << std::endl;
        std::cout << "📋 Server info: " << server_info.dump(2) << std::endl;
        
        // Create socket
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "❌ Failed to create socket" << std::endl;
            return 1;
        }
        
        // Set socket options
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "❌ Failed to set socket options" << std::endl;
            close(server_fd);
            return 1;
        }
        
        // Bind socket
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);
        
        if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "❌ Failed to bind socket" << std::endl;
            close(server_fd);
            return 1;
        }
        
        // Listen for connections
        if (listen(server_fd, 5) < 0) {
            std::cerr << "❌ Failed to listen on socket" << std::endl;
            close(server_fd);
            return 1;
        }
        
        std::cout << "🚀 Noise-NK C++ server listening on localhost:" << port << std::endl;
        std::cout << "📡 Waiting for JavaScript clients..." << std::endl;
        
        while (server_running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) {
                if (server_running) {
                    std::cerr << "❌ Failed to accept connection" << std::endl;
                }
                continue;
            }
            
            // Get client address string
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::string client_addr_str = std::string(client_ip) + ":" + std::to_string(ntohs(client_addr.sin_port));
            
            // Handle client in a separate thread
            std::thread client_thread(handle_client, client_fd, client_addr_str, server_private_key);
            client_thread.detach();
        }
        
        close(server_fd);
        std::cout << "🔌 Server stopped" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Server error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 