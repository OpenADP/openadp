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
              << "Register a long-term secret using Ocrypt distributed cryptography.\n"
              << "\n"
              << "Options:\n"
              << "  --user-id <string>           Unique identifier for the user (required)\n"
              << "  --app-id <string>            Application identifier to namespace secrets per app (required)\n"
              << "  --long-term-secret <string>  Long-term secret to protect (required)\n"
              << "  --password <string>          Password/PIN to unlock the secret (will prompt if not provided)\n"
              << "  --max-guesses <number>       Maximum wrong PIN attempts before lockout (default: 10)\n"
              << "  --servers-url <string>       Custom URL for server registry (empty uses default)\n"
              << "  --servers <string>           Comma-separated list of servers (overrides registry)\n"
              << "  --output <string>            File to write metadata JSON (writes to stdout if not specified)\n"
              << "  --debug                      Enable debug mode for deterministic operations\n"
              << "  --version                    Show version information\n"
              << "  --help                       Show this help message\n"
              << "\n"
              << "Environment Variables:\n"
              << "  OPENADP_USER_ID              Default user ID\n"
              << "  OPENADP_PASSWORD             Default password (not recommended for security)\n"
              << "  OPENADP_SERVERS_URL          Default servers URL\n"
              << "\n"
              << "Security Warning:\n"
              << "  Using --password on the command line is insecure as it may be visible\n"
              << "  in process lists. Consider using environment variables or interactive\n"
              << "  password prompts for better security.\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\"\n"
              << "  " << program_name << " --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\" --output metadata.json\n"
              << "  " << program_name << " --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\" --debug\n";
}

void print_version() {
    std::cout << "OpenADP ocrypt-register v0.1.2\n";
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

int main(int argc, char* argv[]) {
    std::string user_id;
    std::string app_id;
    std::string long_term_secret;
    std::string password;
    int max_guesses = 10;
    std::string servers_url;
    std::string servers;
    std::string output_file;
    bool debug_mode = false;
    
    // Check environment variables
    const char* env_user_id = std::getenv("OPENADP_USER_ID");
    const char* env_password = std::getenv("OPENADP_PASSWORD");
    const char* env_servers_url = std::getenv("OPENADP_SERVERS_URL");
    
    if (env_user_id) user_id = env_user_id;
    if (env_password) password = env_password;
    if (env_servers_url) servers_url = env_servers_url;
    
    static struct option long_options[] = {
        {"user-id", required_argument, 0, 'u'},
        {"app-id", required_argument, 0, 'a'},
        {"long-term-secret", required_argument, 0, 'l'},
        {"password", required_argument, 0, 'p'},
        {"max-guesses", required_argument, 0, 'g'},
        {"servers-url", required_argument, 0, 's'},
        {"servers", required_argument, 0, 'S'},
        {"output", required_argument, 0, 'o'},
        {"debug", no_argument, 0, 'D'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "u:a:l:p:g:s:S:o:DVh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'u':
                user_id = optarg;
                break;
            case 'a':
                app_id = optarg;
                break;
            case 'l':
                long_term_secret = optarg;
                break;
            case 'p':
                password = optarg;
                std::cerr << "Warning: Using --password on command line is insecure. Consider using environment variables or interactive prompts.\n";
                break;
            case 'g':
                max_guesses = std::stoi(optarg);
                break;
            case 's':
                servers_url = optarg;
                break;
            case 'S':
                servers = optarg;
                break;
            case 'o':
                output_file = optarg;
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
    }
    
    // Validate required arguments
    if (user_id.empty()) {
        std::cerr << "Error: Missing required argument --user-id\n\n";
        print_usage(argv[0]);
        return 1;
    }
    
    if (app_id.empty()) {
        std::cerr << "Error: Missing required argument --app-id\n\n";
        print_usage(argv[0]);
        return 1;
    }
    
    if (long_term_secret.empty()) {
        std::cerr << "Error: Missing required argument --long-term-secret\n\n";
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
        // Convert long-term secret to Bytes
        Bytes secret_bytes = utils::string_to_bytes(long_term_secret);
        
        // Determine which server configuration to use
        std::string effective_servers_url = servers_url;
        if (!servers.empty()) {
            // Use direct server list if provided
            effective_servers_url = servers;
        }
        
        // Register the secret using the correct API
        // Note: For compatibility with the current API that expects device_id, we'll use app_id as device_id  
        Bytes metadata = ocrypt::register_secret(user_id, app_id, secret_bytes, password, max_guesses, effective_servers_url);
        
        // Output raw metadata JSON directly (like other SDKs) for cross-language compatibility
        std::string json_output = utils::bytes_to_string(metadata);
        
        // Write output
        if (output_file.empty()) {
            std::cout << json_output << std::endl;
        } else {
            std::ofstream file(output_file);
            if (!file) {
                std::cerr << "Error: Failed to create output file: " << output_file << std::endl;
                return 1;
            }
            file << json_output << std::endl;
            std::cerr << "Metadata saved to " << output_file << std::endl;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        // Create error JSON
        nlohmann::json result;
        result["success"] = false;
        result["error"] = e.what();
        
        std::string json_output = result.dump(2);
        
        if (output_file.empty()) {
            std::cout << json_output << std::endl;
        } else {
            std::ofstream file(output_file);
            if (file) {
                file << json_output << std::endl;
            }
        }
        
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 