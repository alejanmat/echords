/**
 * @file spb490.h
 * @brief SPB490 encoding standard for RDS transmission
 * 
 * This file contains the declarations for functions implementing
 * the SPB490 encoding standard for RDS transmission.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_SPB490_H
#define ECHORDS_SPB490_H

#include "echords.h"

/**
 * @brief SPB490 special bytes
 */
#define SPB490_HEADER_BYTE 0xFE
#define SPB490_FOOTER_BYTE 0xFF
#define SPB490_ESCAPE_BYTE 0xFD

/**
 * @brief Structure representing an SPB490 packet
 */
typedef struct {
    uint8_t id;                  /**< Packet ID */
    uint8_t *data;               /**< Packet data */
    size_t data_len;             /**< Length of data */
    uint16_t crc;                /**< CRC-16 of the data */
} spb490_packet_t;

/**
 * @brief Structure for SPB490 encoder state
 */
typedef struct {
    uint8_t next_packet_id;      /**< ID for the next packet */
} spb490_encoder_t;

/**
 * @brief Structure for SPB490 decoder state
 */
typedef struct {
    bool in_packet;              /**< Whether we're currently in a packet */
    bool escape_next;            /**< Whether the next byte is escaped */
    uint8_t buffer[ECHORDS_MAX_PACKET_SIZE + 10]; /**< Buffer for packet assembly */
    size_t buffer_pos;           /**< Current position in buffer */
} spb490_decoder_t;

/**
 * @brief Initialize an SPB490 encoder
 * 
 * @param encoder Pointer to the encoder structure to initialize
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_encoder_init(spb490_encoder_t *encoder);

/**
 * @brief Initialize an SPB490 decoder
 * 
 * @param decoder Pointer to the decoder structure to initialize
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_decoder_init(spb490_decoder_t *decoder);

/**
 * @brief Reset an SPB490 decoder state
 * 
 * @param decoder Pointer to the decoder structure to reset
 */
void spb490_decoder_reset(spb490_decoder_t *decoder);

/**
 * @brief Encode a message into SPB490 packets
 * 
 * @param encoder The encoder to use
 * @param data The data to encode
 * @param data_len Length of the data
 * @param packets Array to store the created packets
 * @param max_packets Maximum number of packets that can be stored
 * @param num_packets Pointer to store the number of packets created
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_encode_message(spb490_encoder_t *encoder,
                                     const uint8_t *data,
                                     size_t data_len,
                                     spb490_packet_t *packets,
                                     size_t max_packets,
                                     size_t *num_packets);

/**
 * @brief Encode a single SPB490 packet
 * 
 * @param packet The packet to encode
 * @param buffer Buffer to store the encoded packet
 * @param buffer_size Size of the buffer
 * @param encoded_len Pointer to store the length of the encoded packet
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_encode_packet(const spb490_packet_t *packet,
                                    uint8_t *buffer,
                                    size_t buffer_size,
                                    size_t *encoded_len);

/**
 * @brief Process a byte in the SPB490 decoder
 * 
 * @param decoder The decoder to use
 * @param byte The byte to process
 * @param packet Pointer to store the decoded packet (if complete)
 * @param is_complete Pointer to store whether a packet was completed
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_process_byte(spb490_decoder_t *decoder,
                                   uint8_t byte,
                                   spb490_packet_t *packet,
                                   bool *is_complete);

/**
 * @brief Decode a complete SPB490 packet
 * 
 * @param buffer The buffer containing the packet
 * @param buffer_len Length of the buffer
 * @param packet Pointer to store the decoded packet
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_decode_packet(const uint8_t *buffer,
                                    size_t buffer_len,
                                    spb490_packet_t *packet);

/**
 * @brief Reassemble a message from multiple SPB490 packets
 * 
 * @param packets Array of packets
 * @param num_packets Number of packets
 * @param message Buffer to store the reassembled message
 * @param message_size Size of the message buffer
 * @param message_len Pointer to store the length of the reassembled message
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t spb490_reassemble_message(const spb490_packet_t *packets,
                                         size_t num_packets,
                                         uint8_t *message,
                                         size_t message_size,
                                         size_t *message_len);

/**
 * @brief Calculate CRC-16 for SPB490 packet
 * 
 * @param data The data to calculate CRC for
 * @param len Length of the data
 * @return The calculated CRC-16
 */
uint16_t spb490_calculate_crc(const uint8_t *data, size_t len);

/**
 * @brief Free resources used by an SPB490 packet
 * 
 * @param packet The packet to free
 */
void spb490_free_packet(spb490_packet_t *packet);

#endif /* ECHORDS_SPB490_H */
