/**
 * @file gateway.h
 * @brief Gateway server for EchoRDS
 * 
 * This file contains the declarations for the gateway server
 * that encodes and transmits data via SPB490 + RDS.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_GATEWAY_H
#define ECHORDS_GATEWAY_H

#include "echords.h"
#include "crypto.h"

/**
 * @brief Structure representing the EchoRDS gateway
 */
typedef struct {
    echords_public_key_t *public_key;  /**< Public key for encryption */
    char *rds_device;                  /**< Path to RDS device */
    bool compress;                     /**< Whether to compress messages */
} echords_gateway_t;

/**
 * @brief Initialize the gateway
 * 
 * @param gateway Pointer to the gateway structure to initialize
 * @param public_key_path Path to the public key file
 * @param rds_device Path to the RDS device (can be NULL for simulation)
 * @param compress Whether to compress messages
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_gateway_init(echords_gateway_t *gateway,
                                    const char *public_key_path,
                                    const char *rds_device,
                                    bool compress);

/**
 * @brief Clean up and free resources used by the gateway
 * 
 * @param gateway The gateway to clean up
 */
void echords_gateway_cleanup(echords_gateway_t *gateway);

/**
 * @brief Prepare a message with timestamp and nonce
 * 
 * @param gateway The gateway to use
 * @param message Pointer to the message structure to fill
 * @param type Type of the message
 * @param data Data for the message
 * @param data_len Length of the data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_gateway_prepare_message(echords_gateway_t *gateway,
                                              echords_message_t *message,
                                              echords_message_type_t type,
                                              const uint8_t *data,
                                              size_t data_len);

/**
 * @brief Encrypt a message using the public key
 * 
 * @param gateway The gateway to use
 * @param message The message to encrypt
 * @param encrypted_data Buffer to store the encrypted data
 * @param encrypted_data_size Size of the buffer
 * @param encrypted_data_len Pointer to store the length of the encrypted data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_gateway_encrypt_message(echords_gateway_t *gateway,
                                              const echords_message_t *message,
                                              uint8_t *encrypted_data,
                                              size_t encrypted_data_size,
                                              size_t *encrypted_data_len);

/**
 * @brief Transmit an encrypted message via RDS
 * 
 * @param gateway The gateway to use
 * @param encrypted_data The encrypted data to transmit
 * @param encrypted_data_len Length of the encrypted data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_gateway_transmit_message(echords_gateway_t *gateway,
                                               const uint8_t *encrypted_data,
                                               size_t encrypted_data_len);

/**
 * @brief Send a message (prepare, encrypt, and transmit)
 * 
 * @param gateway The gateway to use
 * @param type Type of the message
 * @param data Data for the message
 * @param data_len Length of the data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_gateway_send_message(echords_gateway_t *gateway,
                                           echords_message_type_t type,
                                           const uint8_t *data,
                                           size_t data_len);

#endif /* ECHORDS_GATEWAY_H */
