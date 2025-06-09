/**
 * @file key_generator.c
 * @brief RSA key pair generator for EchoRDS
 * 
 * This file implements a utility to generate RSA key pairs for
 * the EchoRDS system.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "../../include/echords.h"
#include "../../include/crypto.h"

/**
 * @brief Print usage information
 * 
 * @param program_name Name of the program
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Generate RSA key pair for EchoRDS\n\n");
    printf("Options:\n");
    printf("  -o, --output-dir DIR    Directory to save the keys (default: current directory)\n");
    printf("  -b, --key-bits BITS     RSA key size in bits (default: 2048)\n");
    printf("  -h, --help              Display this help and exit\n");
}

/**
 * @brief Main function
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, non-zero on error
 */
int main(int argc, char *argv[]) {
    char *output_dir = ".";
    int key_bits = 2048;
    
    // Define long options
    static struct option long_options[] = {
        {"output-dir", required_argument, 0, 'o'},
        {"key-bits", required_argument, 0, 'b'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line options
    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "o:b:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'o':
                output_dir = optarg;
                break;
            case 'b':
                key_bits = atoi(optarg);
                if (key_bits < 1024 || key_bits > 4096) {
                    fprintf(stderr, "Error: Key size must be between 1024 and 4096 bits\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Create file paths
    char public_key_path[1024];
    char private_key_path[1024];
    
    snprintf(public_key_path, sizeof(public_key_path), "%s/public_key.pem", output_dir);
    snprintf(private_key_path, sizeof(private_key_path), "%s/private_key.pem", output_dir);
    
    // Generate key pair
    echords_error_t result = echords_generate_key_pair(public_key_path, private_key_path, key_bits);
    
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error generating key pair: %s\n", echords_error_string(result));
        return 1;
    }
    
    printf("Keys generated successfully in %s\n", output_dir);
    printf("- private_key.pem: Keep this secure on the receiver\n");
    printf("- public_key.pem: Distribute this to the gateway server\n");
    
    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
