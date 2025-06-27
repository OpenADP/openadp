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
              << "Register a secret with OpenADP ocrypt protection.\n"
              << "\n"
              << "Options:\n"
              << "  --user-id <string>    Unique identifier for the user (required)\n"
              << "  --device-id <string>  Device identifier (default: cpp_device)\n"
              << "  --backup-id <string>  Backup identifier (default: ocrypt_backup)\n"
              << "  --password <string>   Password/PIN to protect the secret (will prompt if not provided)\n"
              << "  --max-guesses <num>   Maximum wrong PIN attempts (default: 10)\n"
              << "  --servers-url <url>   Custom URL for server registry (empty uses default)\n"
              << "  --debug               Enable debug mode (deterministic operations)\n"
              << "  --help                Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --user-id alice@example.com\n"
              << "  " << program_name << " --user-id bob --device-id phone --password mypin\n";
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
    std::string device_id = "cpp_device";
    std::string backup_id = "ocrypt_backup";
    std::string password;
    int max_guesses = 10;
    std::string servers_url;
    bool debug_mode = false;
    
    static struct option long_options[] = {
        {"user-id", required_argument, 0, 'u'},
        {"device-id", required_argument, 0, 'd'},
        {"backup-id", required_argument, 0, 'b'},
        {"password", required_argument, 0, 'p'},
        {"max-guesses", required_argument, 0, 'g'},
        {"servers-url", required_argument, 0, 's'},
        {"debug", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "u:d:b:p:g:s:Dh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'u':
                user_id = optarg;
                break;
            case 'd':
                device_id = optarg;
                break;
            case 'b':
                backup_id = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'g':
                max_guesses = std::stoi(optarg);
                break;
            case 's':
                servers_url = optarg;
                break;
            case 'D':
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
    
    // Validate required arguments
    if (user_id.empty()) {
        std::cerr << "Error: Missing required argument --user-id\n\n";
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
        // Generate a test secret (32 random bytes)
        Bytes test_secret = utils::random_bytes(32);
        
        // Register the secret using the correct API
        Bytes metadata = ocrypt::register_secret(user_id, device_id, test_secret, password, max_guesses, servers_url);
        
        // Create result JSON
        nlohmann::json result;
        result["success"] = true;
        result["metadata"] = utils::base64_encode(metadata);
        result["secret"] = utils::base64_encode(test_secret);
        result["message"] = "Secret registered successfully";
        
        std::string json_output = result.dump(2); // Pretty print with 2-space indent
        
        // Write output
        std::cout << json_output << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        // Create error JSON
        nlohmann::json result;
        result["success"] = false;
        result["error"] = e.what();
        
        std::string json_output = result.dump(2);
        
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 