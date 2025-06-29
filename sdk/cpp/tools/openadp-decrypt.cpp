#include <openadp.hpp>
#include <openadp/debug.hpp>
#include <iostream>
#include <fstream>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

using namespace openadp;

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "OpenADP File Decryption Tool\n"
              << "\n"
              << "Options:\n"
              << "  --file <path>          File to decrypt (required)\n"
              << "  --password <password>  Password for key derivation (will prompt if not provided)\n"
              << "  --user-id <id>         User ID override (will use metadata or prompt if not provided)\n"
              << "  --servers <urls>       Comma-separated list of server URLs to override metadata servers\n"
              << "  --servers-url <url>    URL to scrape for server list (overrides metadata)\n"
              << "  --debug                Enable debug mode for deterministic operations\n"
              << "  --version              Show version information\n"
              << "  --help                 Show this help message\n"
              << "\n"
              << "USER ID HANDLING:\n"
              << "    The tool will use the User ID in this priority order:\n"
              << "    1. Command line flag (--user-id)\n"
              << "    2. User ID stored in the encrypted file metadata\n"
              << "    3. OPENADP_USER_ID environment variable\n"
              << "    4. Interactive prompt\n"
              << "\n"
              << "    You only need to specify a User ID if it's missing from the file metadata\n"
              << "    or if you want to override it for some reason.\n"
              << "\n"
              << "SERVER DISCOVERY:\n"
              << "    By default, the tool uses servers from the encrypted file metadata.\n"
              << "    Use --servers to specify your own server list and override the metadata.\n"
              << "    Use --servers-url to fetch from a different registry instead of metadata.\n"
              << "\n"
              << "DEBUG MODE:\n"
              << "    When --debug is enabled, all cryptographic operations become deterministic\n"
              << "    for testing purposes. This should NEVER be used in production.\n"
              << "\n"
              << "EXAMPLES:\n"
              << "    # Decrypt a file using servers from metadata\n"
              << "    " << program_name << " --file document.txt.enc\n"
              << "\n"
              << "    # Decrypt using override servers\n"
              << "    " << program_name << " --file document.txt.enc --servers \"https://server1.com,https://server2.com\"\n"
              << "\n"
              << "    # Override user ID (useful for corrupted metadata)\n"
              << "    " << program_name << " --file document.txt.enc --user-id \"myuserid\"\n"
              << "\n"
              << "    # Use a different server registry\n"
              << "    " << program_name << " --file document.txt.enc --servers-url \"https://my-registry.com\"\n"
              << "\n"
              << "    # Enable debug mode for testing\n"
              << "    " << program_name << " --file document.txt.enc --debug\n"
              << "\n"
              << "    # Use environment variables\n"
              << "    export OPENADP_PASSWORD=\"mypassword\"\n"
              << "    export OPENADP_USER_ID=\"myuserid\"\n"
              << "    " << program_name << " --file document.txt.enc\n"
              << "\n"
              << "The decrypted file will be saved without the .enc extension\n";
}

std::string read_password() {
    std::cout << "Enter password: ";
    std::cout.flush();
    
    // Disable echo
    struct termios old_termios, new_termios;
    tcgetattr(STDIN_FILENO, &old_termios);
    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    
    std::string password;
    std::getline(std::cin, password);
    
    // Restore echo
    tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
    
    std::cout << std::endl;
    return password;
}

std::string read_user_id() {
    std::cout << "Enter User ID: ";
    std::cout.flush();
    
    std::string user_id;
    std::getline(std::cin, user_id);
    
    return user_id;
}

// Remove .enc extension from filename
std::string get_output_filename(const std::string& input_file) {
    if (input_file.length() >= 4 && input_file.substr(input_file.length() - 4) == ".enc") {
        return input_file.substr(0, input_file.length() - 4);
    }
    return input_file + ".dec"; // fallback if no .enc extension
}

int main(int argc, char* argv[]) {
    std::string input_file;
    std::string user_id;
    std::string password;
    std::string servers;
    std::string servers_url;
    bool debug_mode = false;
    
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"password", required_argument, 0, 'p'},
        {"user-id", required_argument, 0, 'u'},
        {"servers", required_argument, 0, 's'},
        {"servers-url", required_argument, 0, 'r'},
        {"debug", no_argument, 0, 'd'},
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "f:p:u:s:r:dvh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'f':
                input_file = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'u':
                user_id = optarg;
                break;
            case 's':
                servers = optarg;
                break;
            case 'r':
                servers_url = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'v':
                std::cout << "OpenADP C++ Decrypt Tool v0.1.2\n";
                return 0;
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
    
    // Validate required argument
    if (input_file.empty()) {
        std::cerr << "Error: Input file '--file' is required.\n\n";
        print_usage(argv[0]);
        return 1;
    }
    
    // Check if input file exists
    std::ifstream file_check(input_file);
    if (!file_check.good()) {
        std::cerr << "Error: Input file '" << input_file << "' not found.\n";
        return 1;
    }
    file_check.close();
    
    // Generate output filename
    std::string output_file = get_output_filename(input_file);
    
    // Get password from environment or prompt
    if (password.empty()) {
        const char* env_password = std::getenv("OPENADP_PASSWORD");
        if (env_password) {
            password = env_password;
        } else {
            password = read_password();
            if (password.empty()) {
                std::cerr << "Error: Password cannot be empty.\n";
                return 1;
            }
        }
    } else {
        std::cerr << "⚠️  Warning: Password provided via command line (visible in process list)\n";
    }
    
    try {
        // Read input file with embedded metadata (matching other SDKs)
        Bytes file_data = utils::read_file(input_file);
        
        // Validate file size
        const size_t min_size = 4 + 1 + 12 + 1; // metadata_length + minimal_metadata + nonce + minimal_ciphertext
        if (file_data.size() < min_size) {
            std::cerr << "Error: File is too small to be a valid encrypted file (expected at least " 
                      << min_size << " bytes, got " << file_data.size() << ").\n";
            return 1;
        }
        
        // Extract metadata length (first 4 bytes, little endian)
        uint32_t metadata_length = static_cast<uint32_t>(file_data[0]) |
                                  (static_cast<uint32_t>(file_data[1]) << 8) |
                                  (static_cast<uint32_t>(file_data[2]) << 16) |
                                  (static_cast<uint32_t>(file_data[3]) << 24);
        
        // Validate metadata length
        if (metadata_length > file_data.size() - 4 - 12) {
            std::cerr << "Error: Invalid metadata length " << metadata_length << ".\n";
            return 1;
        }
        
        // Extract components: [metadata_length][metadata][nonce][encrypted_data]
        size_t metadata_start = 4;
        size_t metadata_end = metadata_start + metadata_length;
        size_t nonce_start = metadata_end;
        size_t nonce_end = nonce_start + 12;
        
        std::string metadata_str(file_data.begin() + metadata_start, file_data.begin() + metadata_end);
        Bytes nonce(file_data.begin() + nonce_start, file_data.begin() + nonce_end);
        Bytes encrypted_data(file_data.begin() + nonce_end, file_data.end());
        
        // Split encrypted_data into ciphertext and tag (last 16 bytes are tag)
        if (encrypted_data.size() < 16) {
            std::cerr << "Error: Encrypted data too small to contain authentication tag.\n";
            return 1;
        }
        
        Bytes ciphertext(encrypted_data.begin(), encrypted_data.end() - 16);
        Bytes tag(encrypted_data.end() - 16, encrypted_data.end());
        
        // Parse metadata
        nlohmann::json metadata_json = nlohmann::json::parse(metadata_str);
        
        // Use the exact metadata string that was read from the file as AAD
        // Add crypto fields for the legacy decrypt_data function interface
        nlohmann::json full_metadata = metadata_json;
        full_metadata["ciphertext"] = utils::base64_encode(ciphertext);
        full_metadata["tag"] = utils::base64_encode(tag);
        full_metadata["nonce"] = utils::base64_encode(nonce);
        full_metadata["_original_metadata_aad"] = metadata_str;  // Pass exact string for AAD
        
        std::string full_metadata_str = full_metadata.dump();
        Bytes metadata = utils::string_to_bytes(full_metadata_str);
        
        // Override ciphertext to use the extracted raw ciphertext
        ciphertext = ciphertext;
        
        // Get user ID from metadata, environment, or prompt
        if (user_id.empty()) {
            // Try to extract from metadata first
            if (metadata_json.contains("user_id")) {
                user_id = metadata_json["user_id"].get<std::string>();
                std::cout << "Using User ID from file metadata: " << user_id << "\n";
            } else {
                const char* env_user_id = std::getenv("OPENADP_USER_ID");
                if (env_user_id) {
                    user_id = env_user_id;
                } else {
                    user_id = read_user_id();
                    if (user_id.empty()) {
                        std::cerr << "Error: User ID cannot be empty.\n";
                        return 1;
                    }
                }
            }
        } else {
            std::cerr << "⚠️  Warning: User ID provided via command line (visible in process list)\n";
        }
        
        // Create identity
        std::string device_id = "beast";
        std::string backup_id = "file://" + get_output_filename(input_file);
        Identity identity(user_id, device_id, backup_id);
        
        // Handle --servers parameter (similar to encrypt tool)
        if (!servers.empty()) {
            // Override servers with command line parameter
            std::cout << "Using servers from command line (overriding metadata)\n";
        } else {
            // Use servers from metadata
            if (metadata_json.contains("servers")) {
                auto servers_array = metadata_json["servers"];
                std::cout << "Found " << servers_array.size() << " servers in metadata\n";
                for (const auto& server : servers_array) {
                    std::cout << "  - " << server.get<std::string>() << "\n";
                }
            }
        }
        
        // Decrypt data
        Bytes plaintext = decrypt_data(ciphertext, metadata, identity, password, servers_url);
        
        // Write decrypted data
        utils::write_file(output_file, plaintext);
        
        // Get file sizes for display
        std::ifstream input_stream(input_file, std::ios::binary | std::ios::ate);
        std::streamsize input_size = input_stream.tellg();
        input_stream.close();
        
        std::ifstream output_stream(output_file, std::ios::binary | std::ios::ate);
        std::streamsize output_size = output_stream.tellg();
        output_stream.close();
        
        // Display results in the same format as other SDKs
        std::cout << "📁 Input:  " << input_file << " (" << input_size << " bytes)\n";
        std::cout << "📁 Output: " << output_file << " (" << output_size << " bytes)\n";
        std::cout << "🔓 Decryption: AES-GCM\n";
        std::cout << "✅ File decrypted successfully!\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 