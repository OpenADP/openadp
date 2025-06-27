#include <openadp.hpp>
#include <iostream>
#include <fstream>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

using namespace openadp;

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Register a long-term secret using Ocrypt distributed cryptography.\n"
              << "\n"
              << "Options:\n"
              << "  --user-id <string>         Unique identifier for the user (required)\n"
              << "  --app-id <string>          Application identifier to namespace secrets per app (required)\n"
              << "  --long-term-secret <string> Long-term secret to protect (required)\n"
              << "  --password <string>        Password/PIN to unlock the secret (will prompt if not provided)\n"
              << "  --max-guesses <num>        Maximum wrong PIN attempts (default: 10)\n"
              << "  --servers-url <url>        Custom URL for server registry (empty uses default)\n"
              << "  --output <file>            File to write registration metadata JSON (writes to stdout if not specified)\n"
              << "  --help                     Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\"\n"
              << "  " << program_name << " --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\" --output metadata.json\n";
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
    std::string output_file;
    
    static struct option long_options[] = {
        {"user-id", required_argument, 0, 'u'},
        {"app-id", required_argument, 0, 'a'},
        {"long-term-secret", required_argument, 0, 'l'},
        {"password", required_argument, 0, 'p'},
        {"max-guesses", required_argument, 0, 'g'},
        {"servers-url", required_argument, 0, 's'},
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "u:a:l:p:g:s:o:h", long_options, &option_index)) != -1) {
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
                break;
            case 'g':
                max_guesses = std::stoi(optarg);
                break;
            case 's':
                servers_url = optarg;
                break;
            case 'o':
                output_file = optarg;
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
    
    // Validate required arguments
    if (user_id.empty() || app_id.empty() || long_term_secret.empty()) {
        std::cerr << "Error: Missing required arguments.\n\n";
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
        // Convert secret to bytes
        Bytes secret_bytes = utils::string_to_bytes(long_term_secret);
        
        // Register the secret
        Bytes metadata = ocrypt::register_secret(user_id, app_id, secret_bytes, password, max_guesses, servers_url);
        
        // Create result JSON
        nlohmann::json result;
        result["success"] = true;
        result["metadata"] = utils::base64_encode(metadata);
        result["message"] = "Secret registered successfully";
        
        std::string json_output = result.dump(2); // Pretty print with 2-space indent
        
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
            std::cerr << "Registration metadata saved to " << output_file << std::endl;
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