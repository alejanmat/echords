/**
 * @file echords.c
 * @brief Main implementation file for the EchoRDS project
 * 
 * This file implements the core functionality of the EchoRDS system.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../include/echords.h"

/**
 * @brief Flag indicating whether the library has been initialized
 */
static int echords_initialized = 0;

/**
 * @brief Initialize the EchoRDS library
 */
echords_error_t echords_init(void) {
    if (echords_initialized) {
        return ECHORDS_SUCCESS;
    }
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    echords_initialized = 1;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Clean up and free resources used by the EchoRDS library
 */
void echords_cleanup(void) {
    if (!echords_initialized) {
        return;
    }
    
    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    echords_initialized = 0;
}

/**
 * @brief Get the version string of the EchoRDS library
 */
const char* echords_version(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d", 
             ECHORDS_VERSION_MAJOR, 
             ECHORDS_VERSION_MINOR, 
             ECHORDS_VERSION_PATCH);
    return version;
}

/**
 * @brief Get a string description for an error code
 */
const char* echords_error_string(echords_error_t error) {
    switch (error) {
        case ECHORDS_SUCCESS:
            return "Success";
        case ECHORDS_ERROR_INVALID_ARGS:
            return "Invalid arguments";
        case ECHORDS_ERROR_MEMORY:
            return "Memory allocation error";
        case ECHORDS_ERROR_IO:
            return "I/O error";
        case ECHORDS_ERROR_CRYPTO:
            return "Cryptographic error";
        case ECHORDS_ERROR_PROTOCOL:
            return "Protocol error";
        case ECHORDS_ERROR_DATABASE:
            return "Database error";
        case ECHORDS_ERROR_TIMEOUT:
            return "Timeout error";
        case ECHORDS_ERROR_HARDWARE:
            return "Hardware error";
        case ECHORDS_ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}
