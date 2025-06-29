#include <openadp.hpp>
#include <openadp/debug.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

using namespace openadp;

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "OpenADP File Encryption Tool\n"
              << "\n"
              << "Options:\n"
              << "  --file <path>          File to encrypt (required)\n"
              << "  --password <password>  Password for key derivation (will prompt if not provided)\n"
              << "  --user-id <id>         User ID for secret ownership (will prompt if not provided)\n"
              << "  --servers <urls>       Comma-separated list of server URLs (optional)\n"
              << "  --servers-url <url>    URL to scrape for server list (default: https://servers.openadp.org/api/servers.json)\n"
              << "  --debug                Enable debug mode for deterministic operations\n"
              << "  --version              Show version information\n"
              << "  --help                 Show this help message\n"
              << "\n"
              << "USER ID SECURITY:\n"
              << "    Your User ID uniquely identifies your secrets on the servers. It is critical that:\n"
              << "    • You use the same User ID for all your files\n"
              << "    • You keep your User ID private (anyone with it can overwrite your secrets)\n"
              << "    • You choose a unique User ID that others won't guess\n"
              << "    • You remember your User ID for future decryption\n"
              << "\n"
              << "    You can set the OPENADP_USER_ID environment variable to avoid typing it repeatedly.\n"
              << "\n"
              << "SERVER DISCOVERY:\n"
              << "    By default, the tool fetches the server list from servers.openadp.org/api/servers.json\n"
              << "    If the registry is unavailable, it falls back to hardcoded servers.\n"
              << "    Use --servers to specify your own server list and skip discovery.\n"
              << "\n"
              << "DEBUG MODE:\n"
              << "    When --debug is enabled, all cryptographic operations become deterministic\n"
              << "    for testing purposes. This should NEVER be used in production.\n"
              << "\n"
              << "EXAMPLES:\n"
              << "    # Encrypt a file using discovered servers (fetches from servers.openadp.org)\n"
              << "    " << program_name << " --file document.txt\n"
              << "\n"
              << "    # Encrypt using specific servers (skip discovery)\n"
              << "    " << program_name << " --file document.txt --servers \"https://server1.com,https://server2.com\"\n"
              << "\n"
              << "    # Use a different server registry\n"
              << "    " << program_name << " --file document.txt --servers-url \"https://my-registry.com\"\n"
              << "\n"
              << "    # Enable debug mode for testing\n"
              << "    " << program_name << " --file document.txt --debug\n"
              << "\n"
              << "    # Use environment variables to avoid prompts\n"
              << "    export OPENADP_PASSWORD=\"mypassword\"\n"
              << "    export OPENADP_USER_ID=\"myuserid\"\n"
              << "    " << program_name << " --file document.txt\n"
              << "\n"
              << "The encrypted file will be saved as <filename>.enc\n";
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
                std::cout << "OpenADP C++ Encrypt Tool v0.1.2\n";
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
    
    // Get user ID from environment or prompt
    if (user_id.empty()) {
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
    } else {
        std::cerr << "⚠️  Warning: User ID provided via command line (visible in process list)\n";
    }
    
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
    
    // Generate output filename
    std::string output_file = input_file + ".enc";
    
    try {
        // Read input file
        Bytes plaintext = utils::read_file(input_file);
        
        // Create identity
        std::string device_id = "beast";
        std::string backup_id = "file://" + input_file;
        Identity identity(user_id, device_id, backup_id);
        
        // Handle --servers parameter by parsing comma-separated URLs
        EncryptResult result{Bytes(), Bytes()}; // Initialize with empty data
        if (!servers.empty()) {
            // Parse comma-separated server URLs into vector
            std::vector<ServerInfo> server_infos;
            std::stringstream ss(servers);
            std::string server_url;
            
            while (std::getline(ss, server_url, ',')) {
                // Trim whitespace
                server_url.erase(0, server_url.find_first_not_of(" \t"));
                server_url.erase(server_url.find_last_not_of(" \t") + 1);
                
                if (!server_url.empty()) {
                    server_infos.emplace_back(server_url);
                }
            }
            
            if (server_infos.empty()) {
                std::cerr << "Error: No valid servers found in --servers parameter.\n";
                return 1;
            }
            
            // Encrypt data using specific servers
            result = encrypt_data(plaintext, identity, password, 10, 0, server_infos);
        } else {
            // Encrypt data using server discovery
            result = encrypt_data(plaintext, identity, password, 10, 0, servers_url);
        }
        
        // Write encrypted data with embedded metadata (matching other SDKs)
        // Format: [metadata_length][metadata][nonce][encrypted_data]
        
        // Parse the existing metadata to extract components and rebuild in proper format
        std::string result_metadata_str = utils::bytes_to_string(result.metadata);
        nlohmann::json existing_metadata = nlohmann::json::parse(result_metadata_str);
        
        // Extract AES-GCM components from existing metadata
        Bytes nonce = utils::base64_decode(existing_metadata["nonce"].get<std::string>());
        Bytes tag = utils::base64_decode(existing_metadata["tag"].get<std::string>());
        
        // Create new metadata JSON matching other SDKs format (without embedded crypto data)
        // This must match exactly what was used as AAD during encryption
        nlohmann::json metadata;
        metadata["auth_code"] = existing_metadata["auth_code"];
        metadata["backup_id"] = existing_metadata["backup_id"];
        metadata["device_id"] = existing_metadata["device_id"];
        metadata["servers"] = existing_metadata["servers"];
        metadata["threshold"] = existing_metadata["threshold"];
        metadata["user_id"] = existing_metadata["user_id"];
        metadata["version"] = "1.0";
        
        std::string metadata_str = metadata.dump();
        std::vector<uint8_t> metadata_bytes(metadata_str.begin(), metadata_str.end());
        
        // Prepare final output: [metadata_length][metadata][nonce][encrypted_data]
        std::vector<uint8_t> output_data;
        
        // Write metadata length (4 bytes, little endian)
        uint32_t metadata_len = static_cast<uint32_t>(metadata_bytes.size());
        output_data.push_back(metadata_len & 0xFF);
        output_data.push_back((metadata_len >> 8) & 0xFF);
        output_data.push_back((metadata_len >> 16) & 0xFF);
        output_data.push_back((metadata_len >> 24) & 0xFF);
        
        // Write metadata
        output_data.insert(output_data.end(), metadata_bytes.begin(), metadata_bytes.end());
        
        // Write nonce (12 bytes)
        output_data.insert(output_data.end(), nonce.begin(), nonce.end());
        
        // Write encrypted data (ciphertext + auth tag combined)
        output_data.insert(output_data.end(), result.ciphertext.begin(), result.ciphertext.end());
        output_data.insert(output_data.end(), tag.begin(), tag.end());
        
        utils::write_file(output_file, output_data);
        
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
        std::cout << "🔐 Encryption: AES-GCM\n";
        std::cout << "✅ File encrypted successfully!\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 