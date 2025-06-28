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
              << "Encrypt a file using OpenADP distributed cryptography.\n"
              << "\n"
              << "Options:\n"
              << "  --input <file>        Input file to encrypt (required)\n"
              << "  --output <file>       Output file for encrypted data (required)\n"
              << "  --metadata <file>     Output file for metadata (required)\n"
              << "  --user-id <string>    Unique identifier for the user (required)\n"
              << "  --password <string>   Password/PIN to unlock the data (will prompt if not provided)\n"
              << "  --max-guesses <num>   Maximum wrong PIN attempts (default: 10)\n"
              << "  --servers-url <url>   Custom URL for server registry (empty uses default)\n"
              << "  --debug               Enable debug mode (deterministic operations)\n"
              << "  --help                Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --input secret.txt --output secret.enc --metadata secret.meta --user-id alice@example.com\n"
              << "  " << program_name << " --input data.bin --output data.enc --metadata data.meta --user-id bob --password mypin\n";
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
    std::string input_file;
    std::string output_file;
    std::string metadata_file;
    std::string user_id;
    std::string password;
    int max_guesses = 10;
    std::string servers_url;
    bool debug_mode = false;
    
    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"metadata", required_argument, 0, 'm'},
        {"user-id", required_argument, 0, 'u'},
        {"password", required_argument, 0, 'p'},
        {"max-guesses", required_argument, 0, 'g'},
        {"servers-url", required_argument, 0, 's'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "i:o:m:u:p:g:s:dh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'm':
                metadata_file = optarg;
                break;
            case 'u':
                user_id = optarg;
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
    
    // Validate required arguments
    if (input_file.empty() || output_file.empty() || metadata_file.empty() || user_id.empty()) {
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
        // Read input file
        Bytes plaintext = utils::read_file(input_file);
        
        // Create identity
        std::string device_id = "beast";
        std::string backup_id = "file://" + input_file;
        Identity identity(user_id, device_id, backup_id);
        
        // Encrypt data
        auto result = encrypt_data(plaintext, identity, password, max_guesses, 0, servers_url);
        
        // Write encrypted data
        utils::write_file(output_file, result.ciphertext);
        
        // Write metadata
        utils::write_file(metadata_file, result.metadata);
        
        std::cout << "Successfully encrypted " << input_file << " to " << output_file << std::endl;
        std::cout << "Metadata saved to " << metadata_file << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 