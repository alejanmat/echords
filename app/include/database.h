/**
 * @file database.h
 * @brief Database interface for EchoRDS
 * 
 * This file contains the declarations for the database interface
 * used to store and retrieve messages.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_DATABASE_H
#define ECHORDS_DATABASE_H

#include "echords.h"

/**
 * @brief Opaque structure for database connection
 */
typedef struct echords_db_t echords_db_t;

/**
 * @brief Structure representing a stored message
 */
typedef struct {
    int64_t id;                  /**< Message ID */
    echords_message_type_t type; /**< Type of message */
    char timestamp[32];          /**< ISO8601 timestamp */
    char nonce[64];              /**< Unique nonce */
    uint8_t *data;               /**< Message data */
    size_t data_len;             /**< Length of data */
    char received_at[32];        /**< ISO8601 timestamp of reception */
} echords_db_message_t;

/**
 * @brief Open a database connection
 * 
 * @param db_path Path to the database file
 * @param db Pointer to store the database connection
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_open(const char *db_path, echords_db_t **db);

/**
 * @brief Close a database connection
 * 
 * @param db The database connection to close
 */
void echords_db_close(echords_db_t *db);

/**
 * @brief Initialize the database schema
 * 
 * @param db The database connection
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_init_schema(echords_db_t *db);

/**
 * @brief Store a message in the database
 * 
 * @param db The database connection
 * @param message The message to store
 * @param message_id Pointer to store the ID of the inserted message
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_store_message(echords_db_t *db,
                                        const echords_message_t *message,
                                        int64_t *message_id);

/**
 * @brief Get a message by ID
 * 
 * @param db The database connection
 * @param message_id The ID of the message to retrieve
 * @param message Pointer to store the retrieved message
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_get_message(echords_db_t *db,
                                      int64_t message_id,
                                      echords_db_message_t *message);

/**
 * @brief Get multiple messages with optional filtering
 * 
 * @param db The database connection
 * @param type Message type to filter by (or -1 for all types)
 * @param start_time Start timestamp for filtering (or NULL for no start time)
 * @param end_time End timestamp for filtering (or NULL for no end time)
 * @param limit Maximum number of messages to retrieve
 * @param offset Number of messages to skip
 * @param messages Array to store the retrieved messages
 * @param max_messages Maximum number of messages that can be stored
 * @param num_messages Pointer to store the number of messages retrieved
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_get_messages(echords_db_t *db,
                                       int type,
                                       const char *start_time,
                                       const char *end_time,
                                       int limit,
                                       int offset,
                                       echords_db_message_t *messages,
                                       int max_messages,
                                       int *num_messages);

/**
 * @brief Count messages with optional filtering
 * 
 * @param db The database connection
 * @param type Message type to filter by (or -1 for all types)
 * @param start_time Start timestamp for filtering (or NULL for no start time)
 * @param end_time End timestamp for filtering (or NULL for no end time)
 * @param count Pointer to store the count
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_count_messages(echords_db_t *db,
                                         int type,
                                         const char *start_time,
                                         const char *end_time,
                                         int *count);

/**
 * @brief Delete a message by ID
 * 
 * @param db The database connection
 * @param message_id The ID of the message to delete
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_db_delete_message(echords_db_t *db, int64_t message_id);

/**
 * @brief Free resources used by a database message
 * 
 * @param message The message to free
 */
void echords_db_free_message(echords_db_message_t *message);

#endif /* ECHORDS_DATABASE_H */
