/**
 * @file spb490.c
 * @brief Implementation of SPB490 encoding standard for RDS transmission
 * 
 * This file implements the SPB490 encoding standard for RDS transmission,
 * including packet encoding and decoding.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../include/echords.h"
#include "../include/spb490.h"

/**
 * @brief Calculate CRC-16 for SPB490 packet
 */
uint16_t spb490_calculate_crc(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    size_t i, j;
    
    for (i = 0; i < len; i++) {
        crc ^= data[i] << 8;
        for (j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    
    return crc;
}

/**
 * @brief Initialize an SPB490 encoder
 */
echords_error_t spb490_encoder_init(spb490_encoder_t *encoder) {
    if (!encoder) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    encoder->next_packet_id = 0;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Initialize an SPB490 decoder
 */
echords_error_t spb490_decoder_init(spb490_decoder_t *decoder) {
    if (!decoder) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    spb490_decoder_reset(decoder);
    return ECHORDS_SUCCESS;
}

/**
 * @brief Reset an SPB490 decoder state
 */
void spb490_decoder_reset(spb490_decoder_t *decoder) {
    if (!decoder) {
        return;
    }
    
    decoder->in_packet = false;
    decoder->escape_next = false;
    decoder->buffer_pos = 0;
    memset(decoder->buffer, 0, sizeof(decoder->buffer));
}

/**
 * @brief Encode a message into SPB490 packets
 */
echords_error_t spb490_encode_message(spb490_encoder_t *encoder,
                                     const uint8_t *data,
                                     size_t data_len,
                                     spb490_packet_t *packets,
                                     size_t max_packets,
                                     size_t *num_packets) {
    if (!encoder || !data || !packets || !num_packets) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Calculate number of packets needed
    size_t packets_needed = (data_len + ECHORDS_MAX_PACKET_SIZE - 1) / ECHORDS_MAX_PACKET_SIZE;
    
    if (packets_needed > max_packets) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Split data into packets
    size_t i;
    size_t offset = 0;
    
    for (i = 0; i < packets_needed; i++) {
        size_t chunk_size = data_len - offset;
        if (chunk_size > ECHORDS_MAX_PACKET_SIZE) {
            chunk_size = ECHORDS_MAX_PACKET_SIZE;
        }
        
        // Allocate memory for packet data
        packets[i].data = (uint8_t *)malloc(chunk_size);
        if (!packets[i].data) {
            // Free previously allocated memory
            size_t j;
            for (j = 0; j < i; j++) {
                free(packets[j].data);
                packets[j].data = NULL;
            }
            return ECHORDS_ERROR_MEMORY;
        }
        
        // Copy data to packet
        memcpy(packets[i].data, data + offset, chunk_size);
        packets[i].data_len = chunk_size;
        packets[i].id = (encoder->next_packet_id + i) % 256;
        
        // Calculate CRC
        packets[i].crc = spb490_calculate_crc(packets[i].data, packets[i].data_len);
        
        offset += chunk_size;
    }
    
    // Update next packet ID
    encoder->next_packet_id = (encoder->next_packet_id + packets_needed) % 256;
    
    *num_packets = packets_needed;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Encode a single SPB490 packet
 */
echords_error_t spb490_encode_packet(const spb490_packet_t *packet,
                                    uint8_t *buffer,
                                    size_t buffer_size,
                                    size_t *encoded_len) {
    if (!packet || !buffer || !encoded_len) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Calculate maximum possible encoded size
    // Header (3) + Data (with potential escaping) + CRC (2) + Footer (1)
    size_t max_encoded_size = 3 + (packet->data_len * 2) + 2 + 1;
    
    if (buffer_size < max_encoded_size) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    size_t pos = 0;
    
    // Add header
    buffer[pos++] = SPB490_HEADER_BYTE;
    buffer[pos++] = packet->id;
    buffer[pos++] = packet->data_len;
    
    // Add data with escaping
    size_t i;
    for (i = 0; i < packet->data_len; i++) {
        uint8_t b = packet->data[i];
        if (b == SPB490_HEADER_BYTE || b == SPB490_FOOTER_BYTE || b == SPB490_ESCAPE_BYTE) {
            buffer[pos++] = SPB490_ESCAPE_BYTE;
        }
        buffer[pos++] = b;
    }
    
    // Add CRC
    uint16_t crc = packet->crc;
    buffer[pos++] = (crc >> 8) & 0xFF;  // High byte
    buffer[pos++] = crc & 0xFF;         // Low byte
    
    // Add footer
    buffer[pos++] = SPB490_FOOTER_BYTE;
    
    *encoded_len = pos;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Process a byte in the SPB490 decoder
 */
echords_error_t spb490_process_byte(spb490_decoder_t *decoder,
                                   uint8_t byte,
                                   spb490_packet_t *packet,
                                   bool *is_complete) {
    if (!decoder || !packet || !is_complete) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    *is_complete = false;
    
    // Check if we're starting a new packet
    if (!decoder->in_packet && byte == SPB490_HEADER_BYTE) {
        spb490_decoder_reset(decoder);
        decoder->buffer[decoder->buffer_pos++] = byte;
        decoder->in_packet = true;
        return ECHORDS_SUCCESS;
    }
    
    // If we're not in a packet, ignore the byte
    if (!decoder->in_packet) {
        return ECHORDS_SUCCESS;
    }
    
    // Check if we need to escape this byte
    if (decoder->escape_next) {
        decoder->buffer[decoder->buffer_pos++] = byte;
        decoder->escape_next = false;
    } else if (byte == SPB490_ESCAPE_BYTE) {
        decoder->escape_next = true;
    } else if (byte == SPB490_FOOTER_BYTE) {
        // End of packet
        decoder->buffer[decoder->buffer_pos++] = byte;
        decoder->in_packet = false;
        
        // Decode the packet
        echords_error_t result = spb490_decode_packet(
            decoder->buffer,
            decoder->buffer_pos,
            packet
        );
        
        if (result == ECHORDS_SUCCESS) {
            *is_complete = true;
        }
        
        return result;
    } else {
        // Regular byte
        decoder->buffer[decoder->buffer_pos++] = byte;
    }
    
    // Check for buffer overflow
    if (decoder->buffer_pos >= sizeof(decoder->buffer)) {
        spb490_decoder_reset(decoder);
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Decode a complete SPB490 packet
 */
echords_error_t spb490_decode_packet(const uint8_t *buffer,
                                    size_t buffer_len,
                                    spb490_packet_t *packet) {
    if (!buffer || !packet || buffer_len < 6) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Check header and footer
    if (buffer[0] != SPB490_HEADER_BYTE || buffer[buffer_len - 1] != SPB490_FOOTER_BYTE) {
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // Extract packet ID and data length
    uint8_t packet_id = buffer[1];
    uint8_t data_length = buffer[2];
    
    // Extract and unescape data
    uint8_t *data = (uint8_t *)malloc(data_length);
    if (!data) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    size_t data_pos = 0;
    size_t i = 3;  // Start after header
    
    while (i < buffer_len - 3 && data_pos < data_length) {  // -3 for CRC and footer
        if (buffer[i] == SPB490_ESCAPE_BYTE) {
            i++;  // Skip escape byte
            if (i >= buffer_len - 3) {
                free(data);
                return ECHORDS_ERROR_PROTOCOL;
            }
        }
        data[data_pos++] = buffer[i++];
    }
    
    // Check if we got the expected amount of data
    if (data_pos != data_length) {
        free(data);
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // Extract CRC
    uint16_t expected_crc = (buffer[buffer_len - 3] << 8) | buffer[buffer_len - 2];
    
    // Calculate CRC
    uint16_t calculated_crc = spb490_calculate_crc(data, data_length);
    
    // Verify CRC
    if (expected_crc != calculated_crc) {
        free(data);
        return ECHORDS_ERROR_PROTOCOL;
    }
    
    // Fill packet structure
    packet->id = packet_id;
    packet->data = data;
    packet->data_len = data_length;
    packet->crc = calculated_crc;
    
    return ECHORDS_SUCCESS;
}

/**
 * @brief Reassemble a message from multiple SPB490 packets
 */
echords_error_t spb490_reassemble_message(const spb490_packet_t *packets,
                                         size_t num_packets,
                                         uint8_t *message,
                                         size_t message_size,
                                         size_t *message_len) {
    if (!packets || !message || !message_len || num_packets == 0) {
        return ECHORDS_ERROR_INVALID_ARGS;
    }
    
    // Sort packets by ID
    // Note: In a real implementation, we would need to handle packet ID wraparound
    // This is a simplified version that assumes packets are already in order
    
    // Calculate total message size
    size_t total_size = 0;
    size_t i;
    for (i = 0; i < num_packets; i++) {
        total_size += packets[i].data_len;
    }
    
    if (total_size > message_size) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Reassemble message
    size_t offset = 0;
    for (i = 0; i < num_packets; i++) {
        memcpy(message + offset, packets[i].data, packets[i].data_len);
        offset += packets[i].data_len;
    }
    
    *message_len = total_size;
    return ECHORDS_SUCCESS;
}

/**
 * @brief Free resources used by an SPB490 packet
 */
void spb490_free_packet(spb490_packet_t *packet) {
    if (packet) {
        if (packet->data) {
            free(packet->data);
            packet->data = NULL;
        }
        packet->data_len = 0;
    }
}
