#include <openadp.hpp>
#include <openadp/debug.hpp>
#include <iostream>
#include <fstream>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include <cstdlib>

using namespace openadp;

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Recover a long-term secret and re-register with fresh cryptographic material.\n"
              << "\n"
              << "This tool:\n"
              << "  1. Recovers your secret from old metadata\n"
              << "  2. Re-registers it with fresh cryptographic material\n"
              << "  3. Outputs new metadata (automatically backs up existing files)\n"
              << "\n"
              << "Options:\n"
              << "  --metadata <string>     Metadata blob from registration (required)\n"
              << "  --password <string>     Password/PIN to unlock the secret (will prompt if not provided)\n"
              << "  --servers-url <string>  Custom URL for server registry (empty uses default)\n"
              << "  --output <string>       File to write new metadata JSON (writes to stdout if not specified)\n"
              << "  --test-mode             Enable test mode (outputs JSON with secret and metadata)\n"
              << "  --debug                 Enable debug mode for deterministic operations\n"
              << "  --version               Show version information\n"
              << "  --help                  Show this help message\n"
              << "\n"
              << "Environment Variables:\n"
              << "  OPENADP_PASSWORD        Default password (not recommended for security)\n"
              << "  OPENADP_SERVERS_URL     Default servers URL\n"
              << "\n"
              << "Security Warning:\n"
              << "  Using --password on the command line is insecure as it may be visible\n"
              << "  in process lists. Consider using environment variables or interactive\n"
              << "  password prompts for better security.\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --metadata '{\"servers\":[...]}'\n"
              << "  " << program_name << " --metadata \"$(cat metadata.json)\" --output metadata.json\n"
              << "  " << program_name << " --metadata \"$(cat metadata.json)\" --password mypin\n"
              << "  " << program_name << " --metadata \"$(cat metadata.json)\" --test-mode\n";
}

void print_version() {
    std::cout << "OpenADP ocrypt-recover v0.1.2\n";
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

void safe_write_file(const std::string& filename, const std::string& data) {
    // Check if file exists
    std::ifstream check_file(filename);
    if (check_file.good()) {
        check_file.close();
        // File exists, create backup
        std::string backup_name = filename + ".old";
        std::cerr << "📋 Backing up existing " << filename << " to " << backup_name << std::endl;
        
        if (std::rename(filename.c_str(), backup_name.c_str()) != 0) {
            throw std::runtime_error("Failed to backup existing file");
        }
        std::cerr << "✅ Backup created: " << backup_name << std::endl;
    }
    
    // Write new file
    std::ofstream file(filename);
    if (!file) {
        throw std::runtime_error("Failed to write file: " + filename);
    }
    file << data;
    file.close();
    
    std::cerr << "✅ New metadata written to " << filename << std::endl;
}

int main(int argc, char* argv[]) {
    std::string metadata_str;
    std::string password;
    std::string servers_url;
    std::string output_file;
    bool debug_mode = false;
    bool test_mode = false;
    
    // Check environment variables
    const char* env_password = std::getenv("OPENADP_PASSWORD");
    const char* env_servers_url = std::getenv("OPENADP_SERVERS_URL");
    
    if (env_password) password = env_password;
    if (env_servers_url) servers_url = env_servers_url;
    
    static struct option long_options[] = {
        {"metadata", required_argument, 0, 'm'},
        {"password", required_argument, 0, 'p'},
        {"servers-url", required_argument, 0, 's'},
        {"output", required_argument, 0, 'o'},
        {"test-mode", no_argument, 0, 't'},
        {"debug", no_argument, 0, 'D'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "m:p:s:o:tDVh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'm':
                metadata_str = optarg;
                break;
            case 'p':
                password = optarg;
                std::cerr << "Warning: Using --password on command line is insecure. Consider using environment variables or interactive prompts.\n";
                break;
            case 's':
                servers_url = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 't':
                test_mode = true;
                break;
            case 'D':
                debug_mode = true;
                break;
            case 'V':
                print_version();
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
        std::cerr << "🐛 Debug mode enabled - using deterministic operations\n";
    }
    
    // Validate required arguments
    if (metadata_str.empty()) {
        std::cerr << "Error: Missing required --metadata argument.\n\n";
        print_usage(argv[0]);
        return 1;
    }
    
    // Get password if not provided
    if (password.empty()) {
        password = read_password();
        if (password.empty()) {
            std::cerr << "Error: Password cannot be empty.\n";
            return 1;
        }
    }
    
    try {
        // Use default servers URL if none provided
        std::string effective_servers_url = servers_url;
        if (effective_servers_url.empty()) {
            effective_servers_url = "https://servers.openadp.org/api/servers.json";
        }
        
        // Read metadata from file or treat as literal string
        Bytes metadata;
        if (metadata_str.find('{') == 0) {
            // Starts with '{', treat as literal JSON string
            metadata = utils::string_to_bytes(metadata_str);
        } else {
            // Treat as file path and read file contents
            metadata = utils::read_file(metadata_str);
        }
        
        // Call the new recover_and_reregister API
        auto result = ocrypt::recover_and_reregister(metadata, password, effective_servers_url);
        
        // Convert results to strings
        std::string secret_str = utils::bytes_to_string(result.secret);
        std::string new_metadata_str = utils::bytes_to_string(result.new_metadata);
        
        // Handle test mode
        if (test_mode) {
            nlohmann::json test_result;
            test_result["secret"] = secret_str;
            test_result["new_metadata"] = new_metadata_str;
            
            std::cout << test_result.dump() << std::endl;
            return 0;
        }
        
        // Normal mode: Print recovered secret to stderr for user verification
        std::cerr << "🔑 Recovered secret: " << secret_str << std::endl;
        
        // Output new metadata
        if (!output_file.empty()) {
            // Write to file with safe backup
            safe_write_file(output_file, new_metadata_str);
        } else {
            // Write to stdout
            std::cout << new_metadata_str << std::endl;
        }
        
        std::cerr << "✅ Recovery and re-registration complete!" << std::endl;
        std::cerr << "📝 New metadata contains completely fresh cryptographic material" << std::endl;
        
    } catch (const std::exception& e) {
        nlohmann::json error_result;
        error_result["success"] = false;
        error_result["error"] = e.what();
        error_result["remaining_guesses"] = 0;
        
        if (test_mode) {
            std::cout << error_result.dump() << std::endl;
        } else {
            std::cerr << "❌ Recovery failed: " << e.what() << std::endl;
        }
        return 1;
    }
    
    return 0;
} 