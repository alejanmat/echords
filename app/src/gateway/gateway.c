/**
 * @file gateway.c
 * @brief Implementation of the gateway server for EchoRDS
 * 
 * This file implements the gateway server that encodes and transmits
 * data via SPB490 + RDS.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>
#include <zlib.h>

#include "../../include/echords.h"
#include "../../include/crypto.h"
#include "../../include/gateway.h"
#include "../../include/spb490.h"
#include "../../include/json.h"

/**
 * @brief Initialize the gateway
 */
echords_error_t echords_gateway_init(echords_gateway_t *gateway,
                                    const char *public_key_path,
                                    const char *rds_device,
                                    bool compress) {
    if (!gateway || !public_key_path) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Initialize the gateway structure
    memset(gateway, 0, sizeof(echords_gateway_t));
    gateway->compress = compress;
    
    // Load the public key
    echords_error_t result = echords_load_public_key(public_key_path, &gateway->public_key);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Set the RDS device
    if (rds_device) {
        gateway->rds_device = (char *)malloc(strlen(rds_device) + 1);
        if (!gateway->rds_device) {
            echords_free_public_key(gateway->public_key);
            return ECHORDS_ERROR_MEMORY;
        }
        strcpy(gateway->rds_device, rds_device);
    }
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Clean up and free resources used by the gateway
 */
void echords_gateway_cleanup(echords_gateway_t *gateway) {
    if (!gateway) {
        return;
    }
    
    if (gateway->public_key) {
        echords_free_public_key(gateway->public_key);
        gateway->public_key = NULL;
    }
    
    if (gateway->rds_device) {
        free(gateway->rds_device);
        gateway->rds_device = NULL;
    }
}

/**
 * @brief Generate a UUID string
 * 
 * @param buffer Buffer to store the UUID string
 * @param buffer_size Size of the buffer
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
static echords_error_t generate_uuid(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 37) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, buffer);
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Get current ISO8601 timestamp
 * 
 * @param buffer Buffer to store the timestamp
 * @param buffer_size Size of the buffer
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
static echords_error_t get_iso8601_timestamp(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 25) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    time_t now;
    struct tm *tm_info;
    
    time(&now);
    tm_info = gmtime(&now);
    
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Prepare a message with timestamp and nonce
 */
echords_error_t echords_gateway_prepare_message(echords_gateway_t *gateway,
                                              echords_message_t *message,
                                              echords_message_type_t type,
                                              const uint8_t *data,
                                              size_t data_len) {
    if (!gateway || !message || (!data && data_len > 0)) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Set message type
    message->type = type;
    
    // Generate timestamp
    echords_error_t result = get_iso8601_timestamp(message->timestamp, sizeof(message->timestamp));
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Generate nonce
    result = generate_uuid(message->nonce, sizeof(message->nonce));
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Copy data
    message->data = (uint8_t *)malloc(data_len);
    if (!message->data && data_len > 0) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    if (data_len > 0) {
        memcpy(message->data, data, data_len);
    }
    message->data_len = data_len;
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Compress data using zlib
 * 
 * @param data Input data
 * @param data_len Length of input data
 * @param compressed_data Output buffer for compressed data
 * @param compressed_data_size Size of output buffer
 * @param compressed_data_len Pointer to store the length of compressed data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
static echords_error_t compress_data(const uint8_t *data,
                                   size_t data_len,
                                   uint8_t *compressed_data,
                                   size_t compressed_data_size,
                                   size_t *compressed_data_len) {
    if (!data || !compressed_data || !compressed_data_len) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    z_stream strm;
    int ret;
    
    // Initialize zlib stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // Set input data
    strm.avail_in = data_len;
    strm.next_in = (Bytef *)data;
    
    // Set output buffer
    strm.avail_out = compressed_data_size;
    strm.next_out = compressed_data;
    
    // Compress data
    ret = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);
    
    if (ret != Z_STREAM_END) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    *compressed_data_len = compressed_data_size - strm.avail_out;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Encrypt a message using the public key
 */
echords_error_t echords_gateway_encrypt_message(echords_gateway_t *gateway,
                                              const echords_message_t *message,
                                              uint8_t *encrypted_data,
                                              size_t encrypted_data_size,
                                              size_t *encrypted_data_len) {
    if (!gateway || !message || !encrypted_data || !encrypted_data_len) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Serialize message to JSON
    char json_buffer[ECHORDS_MAX_MESSAGE_SIZE];
    size_t json_len;
    
    echords_error_t result = echords_json_serialize_message(message, json_buffer, sizeof(json_buffer), &json_len);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Compress if enabled
    uint8_t compressed_buffer[ECHORDS_MAX_MESSAGE_SIZE];
    const uint8_t *data_to_encrypt;
    size_t data_to_encrypt_len;
    
    if (gateway->compress) {
        size_t compressed_len;
        result = compress_data((uint8_t *)json_buffer, json_len, compressed_buffer, sizeof(compressed_buffer), &compressed_len);
        if (result != ECHORDS_SUCCESS) {
            return result;
        }
        
        data_to_encrypt = compressed_buffer;
        data_to_encrypt_len = compressed_len;
    } else {
        data_to_encrypt = (uint8_t *)json_buffer;
        data_to_encrypt_len = json_len;
    }
    
    // Encrypt data
    size_t output_len = encrypted_data_size;
    result = echords_encrypt(gateway->public_key, data_to_encrypt, data_to_encrypt_len, encrypted_data, &output_len);
    
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    *encrypted_data_len = output_len;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Transmit an encrypted message via RDS
 */
echords_error_t echords_gateway_transmit_message(echords_gateway_t *gateway,
                                               const uint8_t *encrypted_data,
                                               size_t encrypted_data_len) {
    if (!gateway || !encrypted_data) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // If no RDS device is specified, just print a message
    if (!gateway->rds_device) {
        printf("Simulating RDS transmission (no device specified)\n");
        printf("Encrypted data length: %zu bytes\n", encrypted_data_len);
        return ECHORDS_SUCCESS;
    }
    
    // Initialize SPB490 encoder
    spb490_encoder_t encoder;
    echords_error_t result = spb490_encoder_init(&encoder);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Encode message into SPB490 packets
    spb490_packet_t packets[256];  // Maximum number of packets
    size_t num_packets;
    
    result = spb490_encode_message(&encoder, encrypted_data, encrypted_data_len, packets, 256, &num_packets);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    printf("Message encoded into %zu SPB490 packets\n", num_packets);
    
    // Transmit each packet
    size_t i;
    for (i = 0; i < num_packets; i++) {
        uint8_t packet_buffer[512];
        size_t packet_len;
        
        result = spb490_encode_packet(&packets[i], packet_buffer, sizeof(packet_buffer), &packet_len);
        if (result != ECHORDS_SUCCESS) {
            // Free packet data
            size_t j;
            for (j = 0; j < num_packets; j++) {
                spb490_free_packet(&packets[j]);
            }
            return result;
        }
        
        // Here we would send the packet to the RDS device
        printf("Transmitting packet %zu/%zu (ID: %u, Length: %zu bytes)\n", 
               i + 1, num_packets, packets[i].id, packet_len);
        
        // In a real implementation, we would write to the RDS device
        // For example:
        // FILE *rds_device = fopen(gateway->rds_device, "wb");
        // fwrite(packet_buffer, 1, packet_len, rds_device);
        // fclose(rds_device);
        
        // Free packet data
        spb490_free_packet(&packets[i]);
    }
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Send a message (prepare, encrypt, and transmit)
 */
echords_error_t echords_gateway_send_message(echords_gateway_t *gateway,
                                           echords_message_type_t type,
                                           const uint8_t *data,
                                           size_t data_len) {
    if (!gateway) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Prepare message
    echords_message_t message;
    echords_error_t result = echords_gateway_prepare_message(gateway, &message, type, data, data_len);
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Encrypt message
    uint8_t encrypted_data[ECHORDS_MAX_MESSAGE_SIZE];
    size_t encrypted_data_len;
    
    result = echords_gateway_encrypt_message(gateway, &message, encrypted_data, sizeof(encrypted_data), &encrypted_data_len);
    
    // Free message data
    if (message.data) {
        free(message.data);
    }
    
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Transmit message
    return echords_gateway_transmit_message(gateway, encrypted_data, encrypted_data_len);
}
