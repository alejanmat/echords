/**
 * @file main.c
 * @brief Main entry point for the EchoRDS receiver daemon
 * 
 * This file implements the main entry point for the receiver daemon
 * that listens on FM band and decodes messages.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

#include "../../include/echords.h"
#include "../../include/receiver.h"

/**
 * @brief Global receiver instance for signal handling
 */
static echords_receiver_t *g_receiver = NULL;

/**
 * @brief Signal handler for clean shutdown
 * 
 * @param sig Signal number
 */
static void signal_handler(int sig) {
    if (g_receiver) {
        printf("\nReceived signal %d, stopping receiver...\n", sig);
        echords_receiver_stop(g_receiver);
    }
}

/**
 * @brief Print usage information
 * 
 * @param program_name Name of the program
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("EchoRDS Receiver Daemon\n\n");
    printf("Options:\n");
    printf("  -k, --private-key PATH   Path to the private key (required)\n");
    printf("  -d, --db-path PATH       Path to the SQLite database (required)\n");
    printf("  -r, --rds-device PATH    Path or identifier for the RDS device\n");
    printf("  -h, --help               Display this help and exit\n");
}

/**
 * @brief Main function
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, non-zero on error
 */
int main(int argc, char *argv[]) {
    char *private_key_path = NULL;
    char *db_path = NULL;
    char *rds_device = NULL;
    
    // Define long options
    static struct option long_options[] = {
        {"private-key", required_argument, 0, 'k'},
        {"db-path", required_argument, 0, 'd'},
        {"rds-device", required_argument, 0, 'r'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line options
    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "k:d:r:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'k':
                private_key_path = optarg;
                break;
            case 'd':
                db_path = optarg;
                break;
            case 'r':
                rds_device = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check required arguments
    if (!private_key_path) {
        fprintf(stderr, "Error: Private key path is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (!db_path) {
        fprintf(stderr, "Error: Database path is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize EchoRDS library
    echords_error_t result = echords_init();
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error initializing EchoRDS: %s\n", echords_error_string(result));
        return 1;
    }
    
    // Initialize receiver
    echords_receiver_t receiver;
    result = echords_receiver_init(&receiver, private_key_path, db_path, rds_device);
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error initializing receiver: %s\n", echords_error_string(result));
        echords_cleanup();
        return 1;
    }
    
    // Set up signal handling
    g_receiver = &receiver;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Start listening for messages
    printf("EchoRDS Receiver Daemon\n");
    printf("Version: %s\n", echords_version());
    printf("Private key: %s\n", private_key_path);
    printf("Database: %s\n", db_path);
    if (rds_device) {
        printf("RDS device: %s\n", rds_device);
    } else {
        printf("RDS device: None (simulation mode)\n");
    }
    printf("\n");
    
    result = echords_receiver_listen(&receiver);
    
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error in receiver: %s\n", echords_error_string(result));
    }
    
    // Clean up
    echords_receiver_cleanup(&receiver);
    echords_cleanup();
    
    return (result == ECHORDS_SUCCESS) ? 0 : 1;
}
