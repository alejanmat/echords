/**
 * @file json.c
 * @brief Implementation of JSON utilities for EchoRDS
 * 
 * This file contains the implementations for JSON serialization and
 * deserialization functions used in the EchoRDS system.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include "../include/json.h"
#include "../include/echords.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Generate a timestamp in ISO8601 format
 * 
 * @param buffer Buffer to store the timestamp
 * @param buffer_size Size of the buffer
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
static echords_error_t generate_timestamp(char *buffer, size_t buffer_size) {
    time_t now;
    struct tm *tm_info;
    
    if (!buffer || buffer_size < 25) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    time(&now);
    tm_info = gmtime(&now);
    
    if (strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", tm_info) == 0) {
        return ECHORDS_ERROR_UNKNOWN;
    }
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Generate a random nonce
 * 
 * @param buffer Buffer to store the nonce
 * @param buffer_size Size of the buffer
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
static echords_error_t generate_nonce(char *buffer, size_t buffer_size) {
    static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t i;
    
    if (!buffer || buffer_size < 2) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    for (i = 0; i < buffer_size - 1; i++) {
        int index = rand() % (sizeof(charset) - 1);
        buffer[i] = charset[index];
    }
    
    buffer[buffer_size - 1] = '\0';
    return ECHORDS_SUCCESS;
}

echords_error_t echords_json_serialize_message(const echords_message_t *message,
                                              char *json_buffer,
                                              size_t buffer_size,
                                              size_t *json_len) {
    int written = 0;
    
    // Validate input parameters
    if (!message || !json_buffer || buffer_size == 0 || !json_len) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Start building the JSON string
    written = snprintf(json_buffer, buffer_size,
                      "{"
                      "\"type\":%d,"
                      "\"timestamp\":\"%s\","
                      "\"nonce\":\"%s\",",
                      message->type,
                      message->timestamp,
                      message->nonce);
    
    if (written < 0 || (size_t)written >= buffer_size) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Add the data field
    if (message->data && message->data_len > 0) {
        // Calculate remaining buffer space
        size_t remaining = buffer_size - written;
        
        // Check if we have enough space for the data field opening
        if (remaining < 10) { // "data":"" + null terminator
            return ECHORDS_ERROR_MEMORY;
        }
        
        // Add the data field opening
        int data_written = snprintf(json_buffer + written, remaining, "\"data\":\"");
        if (data_written < 0 || (size_t)data_written >= remaining) {
            return ECHORDS_ERROR_MEMORY;
        }
        written += data_written;
        remaining -= data_written;
        
        // We need to escape special characters in the data
        // For simplicity in this implementation, we'll just copy the data directly
        // In a real implementation, you would need to properly escape JSON special characters
        if (remaining < message->data_len + 3) { // data + closing quote + closing brace + null terminator
            return ECHORDS_ERROR_MEMORY;
        }
        
        memcpy(json_buffer + written, message->data, message->data_len);
        written += message->data_len;
        
        // Add the closing quote and brace
        json_buffer[written++] = '"';
        json_buffer[written++] = '}';
        json_buffer[written] = '\0';
    } else {
        // No data, just close the JSON object
        if ((size_t)written + 1 >= buffer_size) {
            return ECHORDS_ERROR_MEMORY;
        }
        json_buffer[written++] = '}';
        json_buffer[written] = '\0';
    }
    
    *json_len = written;
    return ECHORDS_SUCCESS;
}

echords_error_t echords_json_deserialize_message(const char *json_str,
                                               size_t json_len,
                                               echords_message_t *message) {
    // This is a simplified implementation
    // In a real implementation, you would use a proper JSON parser library
    
    if (!json_str || json_len == 0 || !message) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Initialize the message
    memset(message, 0, sizeof(echords_message_t));
    
    // For now, just return a placeholder implementation
    // In a real implementation, you would parse the JSON string
    message->type = ECHORDS_MSG_INFO;
    strncpy(message->timestamp, "2025-06-09T20:00:00Z", sizeof(message->timestamp) - 1);
    strncpy(message->nonce, "placeholder_nonce", sizeof(message->nonce) - 1);
    
    // Allocate memory for the data
    message->data = (uint8_t *)malloc(64);
    if (!message->data) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Copy some placeholder data
    const char *placeholder = "Placeholder data from JSON";
    message->data_len = strlen(placeholder);
    memcpy(message->data, placeholder, message->data_len);
    
    return ECHORDS_SUCCESS;
}

void echords_json_free_message(echords_message_t *message) {
    if (!message) {
        return;
    }
    
    // Free the data if it was allocated
    if (message->data) {
        free(message->data);
        message->data = NULL;
    }
    
    message->data_len = 0;
}

echords_error_t echords_json_create_simple_message(echords_message_type_t type,
                                                 const char *text,
                                                 char *json_buffer,
                                                 size_t buffer_size,
                                                 size_t *json_len) {
    echords_message_t message;
    echords_error_t result;
    
    if (!text || !json_buffer || buffer_size == 0 || !json_len) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Initialize the message
    memset(&message, 0, sizeof(message));
    message.type = type;
    
    // Generate timestamp
    result = generate_timestamp(message.timestamp, sizeof(message.timestamp));
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Generate nonce
    result = generate_nonce(message.nonce, sizeof(message.nonce));
    if (result != ECHORDS_SUCCESS) {
        return result;
    }
    
    // Set the data
    message.data = (uint8_t *)text;
    message.data_len = strlen(text);
    
    // Serialize the message
    result = echords_json_serialize_message(&message, json_buffer, buffer_size, json_len);
    
    // Don't free message.data as it points to the input text
    message.data = NULL;
    
    return result;
}

echords_error_t echords_json_extract_simple_message(const echords_message_t *message,
                                                  char *text_buffer,
                                                  size_t buffer_size) {
    if (!message || !text_buffer || buffer_size == 0) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Check if the message has data
    if (!message->data || message->data_len == 0) {
        text_buffer[0] = '\0';
        return ECHORDS_SUCCESS;
    }
    
    // Check if the buffer is large enough
    if (buffer_size <= message->data_len) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Copy the data to the buffer
    memcpy(text_buffer, message->data, message->data_len);
    text_buffer[message->data_len] = '\0';
    
    return ECHORDS_SUCCESS;
}
