/**
 * @file echords.h
 * @brief Main header file for the EchoRDS project
 * 
 * EchoRDS is a communication protocol and hardware/software system
 * for broadcasting and decoding secure data via FM Radio using RDS
 * (Radio Data System) and the SPB490 encoding standard.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_H
#define ECHORDS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/**
 * @brief Version information for EchoRDS
 */
#define ECHORDS_VERSION_MAJOR 0
#define ECHORDS_VERSION_MINOR 1
#define ECHORDS_VERSION_PATCH 0

/**
 * @brief Maximum size of a message payload
 */
#define ECHORDS_MAX_MESSAGE_SIZE 4096

/**
 * @brief Maximum size of a single SPB490 packet
 */
#define ECHORDS_MAX_PACKET_SIZE 255

/**
 * @brief Error codes for EchoRDS functions
 */
typedef enum {
    ECHORDS_SUCCESS = 0,
    ECHORDS_ERROR_INVALID_ARGS = -1,
    ECHORDS_ERROR_MEMORY = -2,
    ECHORDS_ERROR_IO = -3,
    ECHORDS_ERROR_CRYPTO = -4,
    ECHORDS_ERROR_PROTOCOL = -5,
    ECHORDS_ERROR_DATABASE = -6,
    ECHORDS_ERROR_TIMEOUT = -7,
    ECHORDS_ERROR_HARDWARE = -8,
    ECHORDS_ERROR_UNKNOWN = -99
} echords_error_t;

/**
 * @brief Message types for EchoRDS
 */
typedef enum {
    ECHORDS_MSG_ALERT = 0,
    ECHORDS_MSG_INFO = 1,
    ECHORDS_MSG_COMMAND = 2,
    ECHORDS_MSG_DATA = 3,
    ECHORDS_MSG_CUSTOM = 255
} echords_message_type_t;

/**
 * @brief Structure representing an EchoRDS message
 */
typedef struct {
    echords_message_type_t type;  /**< Type of message */
    char timestamp[32];           /**< ISO8601 timestamp */
    char nonce[64];               /**< Unique nonce for replay protection */
    uint8_t *data;                /**< Message payload */
    size_t data_len;              /**< Length of payload */
} echords_message_t;

/**
 * @brief Initialize the EchoRDS library
 * 
 * This function must be called before using any other EchoRDS functions.
 * 
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_init(void);

/**
 * @brief Clean up and free resources used by the EchoRDS library
 * 
 * This function should be called when the application is done using EchoRDS.
 */
void echords_cleanup(void);

/**
 * @brief Get the version string of the EchoRDS library
 * 
 * @return Pointer to a null-terminated string containing the version
 */
const char* echords_version(void);

/**
 * @brief Get a string description for an error code
 * 
 * @param error The error code
 * @return Pointer to a null-terminated string describing the error
 */
const char* echords_error_string(echords_error_t error);

#endif /* ECHORDS_H */
