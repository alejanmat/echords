/**
 * @file json.h
 * @brief JSON utilities for EchoRDS
 * 
 * This file contains the declarations for JSON serialization and
 * deserialization functions used in the EchoRDS system.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_JSON_H
#define ECHORDS_JSON_H

#include "echords.h"

/**
 * @brief Serialize a message to JSON
 * 
 * @param message The message to serialize
 * @param json_buffer Buffer to store the JSON string
 * @param buffer_size Size of the buffer
 * @param json_len Pointer to store the length of the JSON string
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_json_serialize_message(const echords_message_t *message,
                                              char *json_buffer,
                                              size_t buffer_size,
                                              size_t *json_len);

/**
 * @brief Deserialize a JSON string to a message
 * 
 * @param json_str The JSON string to deserialize
 * @param json_len Length of the JSON string
 * @param message Pointer to store the deserialized message
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_json_deserialize_message(const char *json_str,
                                               size_t json_len,
                                               echords_message_t *message);

/**
 * @brief Free resources used by a message
 * 
 * @param message The message to free
 */
void echords_json_free_message(echords_message_t *message);

/**
 * @brief Create a simple JSON message
 * 
 * @param type Message type
 * @param text Message text
 * @param json_buffer Buffer to store the JSON string
 * @param buffer_size Size of the buffer
 * @param json_len Pointer to store the length of the JSON string
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_json_create_simple_message(echords_message_type_t type,
                                                 const char *text,
                                                 char *json_buffer,
                                                 size_t buffer_size,
                                                 size_t *json_len);

/**
 * @brief Extract text from a simple JSON message
 * 
 * @param message The message to extract from
 * @param text_buffer Buffer to store the extracted text
 * @param buffer_size Size of the buffer
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_json_extract_simple_message(const echords_message_t *message,
                                                  char *text_buffer,
                                                  size_t buffer_size);

#endif /* ECHORDS_JSON_H */
