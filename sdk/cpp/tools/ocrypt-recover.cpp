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
              << "Recover a long-term secret using Ocrypt distributed cryptography.\n"
              << "\n"
              << "Options:\n"
              << "  --metadata <string>       Metadata blob from registration (required)\n"
              << "  --password <string>       Password/PIN to unlock the secret (will prompt if not provided)\n"
              << "  --servers-url <url>       Custom URL for server registry (empty uses default)\n"
              << "  --output <file>           File to write recovery result JSON (writes to stdout if not specified)\n"
              << "  --debug                 Enable debug mode (deterministic operations)\n"
              << "  --help                    Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --metadata '{\"servers\":[...]}'\n"
              << "  " << program_name << " --metadata \"$(cat metadata.json)\" --output result.json\n"
              << "  " << program_name << " --metadata \"$(cat metadata.json)\" --password mypin\n";
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
    std::string metadata_str;
    std::string password;
    std::string servers_url;
    std::string output_file;
    bool debug_mode = false;
    
    static struct option long_options[] = {
        {"metadata", required_argument, 0, 'm'},
        {"password", required_argument, 0, 'p'},
        {"servers-url", required_argument, 0, 's'},
        {"output", required_argument, 0, 'o'},
        {"debug", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "m:p:s:o:Dh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'm':
                metadata_str = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 's':
                servers_url = optarg;
                break;
            case 'o':
                output_file = optarg;
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
        // Parse metadata (could be base64 encoded or JSON string)
        Bytes metadata;
        
        // Try to parse as JSON first
        try {
            nlohmann::json metadata_json = nlohmann::json::parse(metadata_str);
            
            // If it has a "metadata" field, it's a result from register
            if (metadata_json.contains("metadata")) {
                std::string metadata_b64 = metadata_json["metadata"].get<std::string>();
                metadata = utils::base64_decode(metadata_b64);
            } else {
                // It's raw metadata JSON
                metadata = utils::string_to_bytes(metadata_str);
            }
        } catch (...) {
            // Try as base64
            try {
                metadata = utils::base64_decode(metadata_str);
            } catch (...) {
                // Treat as raw string
                metadata = utils::string_to_bytes(metadata_str);
            }
        }
        
        // Recover the secret
        auto result = ocrypt::recover(metadata, password, servers_url);
        
        // Convert secret to string
        std::string secret_str = utils::bytes_to_string(result.secret);
        
        // Create result JSON
        nlohmann::json json_result;
        json_result["success"] = true;
        json_result["secret"] = secret_str;
        json_result["remaining_guesses"] = result.remaining_guesses;
        json_result["updated_metadata"] = utils::base64_encode(result.updated_metadata);
        json_result["message"] = "Secret recovered successfully";
        
        std::string json_output = json_result.dump(2); // Pretty print with 2-space indent
        
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
            std::cerr << "Recovery result saved to " << output_file << std::endl;
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        // Create error JSON
        nlohmann::json result;
        result["success"] = false;
        result["error"] = e.what();
        result["remaining_guesses"] = 0;
        
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