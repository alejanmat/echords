/**
 * @file receiver.h
 * @brief Receiver daemon for EchoRDS
 * 
 * This file contains the declarations for the receiver daemon
 * that listens on FM band and decodes messages.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_RECEIVER_H
#define ECHORDS_RECEIVER_H

#include "echords.h"
#include "crypto.h"
#include "spb490.h"
#include "database.h"

/**
 * @brief Structure representing the EchoRDS receiver
 */
typedef struct {
    echords_private_key_t *private_key;  /**< Private key for decryption */
    char *rds_device;                    /**< Path to RDS device */
    echords_db_t *db;                    /**< Database connection */
    spb490_decoder_t decoder;            /**< SPB490 decoder */
    bool running;                        /**< Whether the receiver is running */
} echords_receiver_t;

/**
 * @brief Initialize the receiver
 * 
 * @param receiver Pointer to the receiver structure to initialize
 * @param private_key_path Path to the private key file
 * @param db_path Path to the database file
 * @param rds_device Path to the RDS device (can be NULL for simulation)
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_receiver_init(echords_receiver_t *receiver,
                                     const char *private_key_path,
                                     const char *db_path,
                                     const char *rds_device);

/**
 * @brief Clean up and free resources used by the receiver
 * 
 * @param receiver The receiver to clean up
 */
void echords_receiver_cleanup(echords_receiver_t *receiver);

/**
 * @brief Decrypt a message using the private key
 * 
 * @param receiver The receiver to use
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len Length of the encrypted data
 * @param message Pointer to store the decrypted message
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_receiver_decrypt_message(echords_receiver_t *receiver,
                                               const uint8_t *encrypted_data,
                                               size_t encrypted_data_len,
                                               echords_message_t *message);

/**
 * @brief Store a message in the database
 * 
 * @param receiver The receiver to use
 * @param message The message to store
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_receiver_store_message(echords_receiver_t *receiver,
                                             const echords_message_t *message);

/**
 * @brief Start listening for RDS messages
 * 
 * This function blocks until the receiver is stopped.
 * 
 * @param receiver The receiver to use
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_receiver_listen(echords_receiver_t *receiver);

/**
 * @brief Stop the receiver
 * 
 * @param receiver The receiver to stop
 */
void echords_receiver_stop(echords_receiver_t *receiver);

/**
 * @brief Process a received message
 * 
 * @param receiver The receiver to use
 * @param message The message to process
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_receiver_process_message(echords_receiver_t *receiver,
                                               const echords_message_t *message);

/**
 * @brief Validate a message (check timestamp, nonce, etc.)
 * 
 * @param receiver The receiver to use
 * @param message The message to validate
 * @return ECHORDS_SUCCESS if valid, error code otherwise
 */
echords_error_t echords_receiver_validate_message(echords_receiver_t *receiver,
                                                const echords_message_t *message);

#endif /* ECHORDS_RECEIVER_H */
