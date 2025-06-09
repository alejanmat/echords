/**
 * @file main.c
 * @brief Main entry point for the EchoRDS gateway server
 * 
 * This file implements the main entry point for the gateway server
 * that encodes and transmits data via SPB490 + RDS.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "../../include/echords.h"
#include "../../include/gateway.h"

/**
 * @brief Print usage information
 * 
 * @param program_name Name of the program
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("EchoRDS Gateway Server\n\n");
    printf("Options:\n");
    printf("  -k, --public-key PATH    Path to the receiver's public key (required)\n");
    printf("  -d, --rds-device PATH    Path or identifier for the RDS device\n");
    printf("  -t, --message-type TYPE  Type of message to send (default: alert)\n");
    printf("  -m, --message TEXT       Message content to send (required)\n");
    printf("  -n, --no-compress        Disable compression\n");
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
    char *public_key_path = NULL;
    char *rds_device = NULL;
    char *message = NULL;
    int message_type = ECHORDS_MSG_ALERT;
    int compress = 1;
    
    // Define long options
    static struct option long_options[] = {
        {"public-key", required_argument, 0, 'k'},
        {"rds-device", required_argument, 0, 'd'},
        {"message-type", required_argument, 0, 't'},
        {"message", required_argument, 0, 'm'},
        {"no-compress", no_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line options
    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "k:d:t:m:nh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'k':
                public_key_path = optarg;
                break;
            case 'd':
                rds_device = optarg;
                break;
            case 't':
                if (strcmp(optarg, "alert") == 0) {
                    message_type = ECHORDS_MSG_ALERT;
                } else if (strcmp(optarg, "info") == 0) {
                    message_type = ECHORDS_MSG_INFO;
                } else if (strcmp(optarg, "command") == 0) {
                    message_type = ECHORDS_MSG_COMMAND;
                } else if (strcmp(optarg, "data") == 0) {
                    message_type = ECHORDS_MSG_DATA;
                } else {
                    fprintf(stderr, "Error: Unknown message type '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'm':
                message = optarg;
                break;
            case 'n':
                compress = 0;
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
    if (!public_key_path) {
        fprintf(stderr, "Error: Public key path is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (!message) {
        fprintf(stderr, "Error: Message is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize EchoRDS library
    echords_error_t result = echords_init();
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error initializing EchoRDS: %s\n", echords_error_string(result));
        return 1;
    }
    
    // Initialize gateway
    echords_gateway_t gateway;
    result = echords_gateway_init(&gateway, public_key_path, rds_device, compress);
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error initializing gateway: %s\n", echords_error_string(result));
        echords_cleanup();
        return 1;
    }
    
    // Create a simple JSON message
    char json_buffer[ECHORDS_MAX_MESSAGE_SIZE];
    snprintf(json_buffer, sizeof(json_buffer), "{\"message\": \"%s\"}", message);
    
    // Send the message
    printf("Sending message: %s\n", message);
    result = echords_gateway_send_message(&gateway, message_type, (uint8_t *)json_buffer, strlen(json_buffer));
    
    if (result != ECHORDS_SUCCESS) {
        fprintf(stderr, "Error sending message: %s\n", echords_error_string(result));
        echords_gateway_cleanup(&gateway);
        echords_cleanup();
        return 1;
    }
    
    printf("Message sent successfully\n");
    
    // Clean up
    echords_gateway_cleanup(&gateway);
    echords_cleanup();
    
    return 0;
}
