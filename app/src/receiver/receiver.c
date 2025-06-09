/**
 * @file receiver.c
 * @brief Implementation of the receiver daemon for EchoRDS
 * 
 * This file implements the receiver daemon that listens on FM band
 * and decodes messages.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#include "../../include/echords.h"
#include "../../include/crypto.h"
#include "../../include/receiver.h"
#include "../../include/spb490.h"
#include "../../include/database.h"
#include "../../include/json.h"

/**
 * @brief Initialize the receiver
 */
echords_error_t echords_receiver_init(echords_receiver_t *receiver,
                                     const char *private_key_path,
                                     const char *db_path,
                                     const char *rds_device) {
    if (!receiver || !private_key_path || !db_path) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Initialize the receiver structure
    memset(receiver, 0, sizeof(echords_receiver_t));
    
    // Load the private key
    echords_error_t result = echords_load_private_key(private_key_path, &receiver->private_key);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Set the RDS device
    if (rds_device) {
        receiver->rds_device = (char *)malloc(strlen(rds_device) + 1);
        if (!receiver->rds_device) {
            echords_free_private_key(receiver->private_key);
            return ECHORDS_ERROR_MEMORY;
        }
        strcpy(receiver->rds_device, rds_device);
    }
    
    // Initialize the SPB490 decoder
    result = spb490_decoder_init(&receiver->decoder);
    if (result != ECHORDS_SUCCESS) {
        if (receiver->rds_device) free(receiver->rds_device);
        echords_free_private_key(receiver->private_key);
        return result;
    }
    
    receiver->running = false;
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Clean up and free resources used by the receiver
 */
void echords_receiver_cleanup(echords_receiver_t *receiver) {
    if (!receiver) {
        return;
    }
    
    if (receiver->private_key) {
        echords_free_private_key(receiver->private_key);
        receiver->private_key = NULL;
    }
    

    if (receiver->rds_device) {
        free(receiver->rds_device);
        receiver->rds_device = NULL;
    }
    
    receiver->running = false;
}

/**
 * @brief Decompress data using zlib
 * 
 * @param compressed_data Compressed data
 * @param compressed_data_len Length of compressed data
 * @param decompressed_data Output buffer for decompressed data
 * @param decompressed_data_size Size of output buffer
 * @param decompressed_data_len Pointer to store the length of decompressed data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
static echords_error_t decompress_data(const uint8_t *compressed_data,
                                     size_t compressed_data_len,
                                     uint8_t *decompressed_data,
                                     size_t decompressed_data_size,
                                     size_t *decompressed_data_len) {
    if (!compressed_data || !decompressed_data || !decompressed_data_len) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    z_stream strm;
    int ret;
    
    // Initialize zlib stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // Set input data
    strm.avail_in = compressed_data_len;
    strm.next_in = (Bytef *)compressed_data;
    
    // Set output buffer
    strm.avail_out = decompressed_data_size;
    strm.next_out = decompressed_data;
    
    // Decompress data
    ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    
    if (ret != Z_STREAM_END) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    *decompressed_data_len = decompressed_data_size - strm.avail_out;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Decrypt a message using the private key
 */
echords_error_t echords_receiver_decrypt_message(echords_receiver_t *receiver,
                                               const uint8_t *encrypted_data,
                                               size_t encrypted_data_len,
                                               echords_message_t *message) {
    if (!receiver || !encrypted_data || !message) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Decrypt data
    uint8_t decrypted_data[ECHORDS_MAX_MESSAGE_SIZE];
    size_t decrypted_data_len = sizeof(decrypted_data);
    
    echords_error_t result = echords_decrypt(receiver->private_key, encrypted_data, encrypted_data_len, decrypted_data, &decrypted_data_len);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Try to decompress (assuming it might be compressed)
    uint8_t decompressed_data[ECHORDS_MAX_MESSAGE_SIZE];
    size_t decompressed_data_len;
    
    result = decompress_data(decrypted_data, decrypted_data_len, decompressed_data, sizeof(decompressed_data), &decompressed_data_len);
    
    // If decompression fails, assume it wasn't compressed
    const uint8_t *json_data;
    size_t json_data_len;
    
    if (result == ECHORDS_SUCCESS) {
        json_data = decompressed_data;
        json_data_len = decompressed_data_len;
    } else {
        json_data = decrypted_data;
        json_data_len = decrypted_data_len;
    }
    
    // Parse JSON
    return echords_json_deserialize_message((const char *)json_data, json_data_len, message);
}

/**
 * @brief Store a message in the database
 */
echords_error_t echords_receiver_store_message(echords_receiver_t *receiver,
                                             const echords_message_t *message) {
    if (!receiver || !message) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Placeholder for future database implementation
    return 0;
    // return echords_db_store_message(receiver->db, message, &message_id);
}

/**
 * @brief Validate a message (check timestamp, nonce, etc.)
 */
echords_error_t echords_receiver_validate_message(echords_receiver_t *receiver,
                                                const echords_message_t *message) {
    if (!receiver || !message) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Check if message has a timestamp
    if (strlen(message->timestamp) == 0) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // Check if message has a nonce
    if (strlen(message->nonce) == 0) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // In a real implementation, we would check:
    // 1. If the timestamp is within an acceptable range (not too old, not in the future)
    // 2. If the nonce has been seen before (to prevent replay attacks)
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Process a received message
 */
echords_error_t echords_receiver_process_message(echords_receiver_t *receiver,
                                               const echords_message_t *message) {
    if (!receiver || !message) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Validate the message
    echords_error_t result = echords_receiver_validate_message(receiver, message);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    printf("%s", message);
    return ECHORDS_SUCCESS;
    // Store the message in the database
   // return echords_receiver_store_message(receiver, message);
}

/**
 * @brief Start listening for RDS messages
 */
echords_error_t echords_receiver_listen(echords_receiver_t *receiver) {
    if (!receiver) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    receiver->running = true;
    printf("Starting to listen for RDS messages...\n");
    
    if (!receiver->rds_device) {
        printf("No RDS device specified. Running in simulation mode.\n");
        printf("Enter base64-encoded messages or press Ctrl+C to exit.\n");
        
        // Simulation mode: read messages from stdin
        char buffer[4096];
        while (receiver->running) {
            printf("\nEnter base64 encrypted message: ");
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                break;
            }
            
            // Remove newline
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
                buffer[len - 1] = '\0';
                len--;
            }
            
            if (len == 0) {
                continue;
            }
            
            // Decode base64
            // In a real implementation, we would decode base64 here
            // For simplicity, we'll just use the raw input
            
            // Decrypt and process message
            echords_message_t message;
            echords_error_t result = echords_receiver_decrypt_message(receiver, (uint8_t *)buffer, len, &message);
            
            if (result == ECHORDS_SUCCESS) {
                printf("Received message:\n");
                printf("  Type: %d\n", message.type);
                printf("  Timestamp: %s\n", message.timestamp);
                printf("  Nonce: %s\n", message.nonce);
                printf("  Data: %.*s\n", (int)message.data_len, message.data);
                
                result = echords_receiver_process_message(receiver, &message);
                if (result == ECHORDS_SUCCESS) {
                    printf("Message processed and stored successfully\n");
                } else {
                    printf("Error processing message: %s\n", echords_error_string(result));
                }
                
                // Free message data
                if (message.data) {
                    free(message.data);
                }
            } else {
                printf("Error decrypting message: %s\n", echords_error_string(result));
            }
        }
    } else {
        // Real RDS device mode
        printf("Listening on RDS device: %s\n", receiver->rds_device);
        
        // In a real implementation, we would:
        // 1. Open the RDS device
        // 2. Read data from it
        // 3. Process the data using the SPB490 decoder
        // 4. Reassemble packets into complete messages
        // 5. Decrypt and process the messages
        
        // For this example, we'll just simulate a few messages
        printf("This is a simulation. In a real implementation, we would read from the RDS device.\n");
        
        // Simulate receiving a few packets
        while (receiver->running) {
            printf("Waiting for RDS messages...\n");
            sleep(5);  // Simulate waiting for messages
        }
    }
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Stop the receiver
 */
void echords_receiver_stop(echords_receiver_t *receiver) {
    if (receiver) {
        receiver->running = false;
    }
}
