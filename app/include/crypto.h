/**
 * @file crypto.h
 * @brief Cryptographic functions for EchoRDS
 * 
 * This file contains the declarations for cryptographic functions
 * used in the EchoRDS system, including RSA encryption/decryption
 * and key management.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#ifndef ECHORDS_CRYPTO_H
#define ECHORDS_CRYPTO_H

#include "echords.h"

/**
 * @brief Opaque structure for RSA public key
 */
typedef struct echords_public_key_t echords_public_key_t;

/**
 * @brief Opaque structure for RSA private key
 */
typedef struct echords_private_key_t echords_private_key_t;

/**
 * @brief Generate an RSA key pair
 * 
 * @param public_key_path Path where the public key will be saved
 * @param private_key_path Path where the private key will be saved
 * @param key_bits Size of the key in bits (e.g., 2048)
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_generate_key_pair(const char *public_key_path, 
                                         const char *private_key_path, 
                                         int key_bits);

/**
 * @brief Load a public key from a file
 * 
 * @param path Path to the public key file
 * @param key Pointer to store the loaded key
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_load_public_key(const char *path, echords_public_key_t **key);

/**
 * @brief Load a private key from a file
 * 
 * @param path Path to the private key file
 * @param key Pointer to store the loaded key
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_load_private_key(const char *path, echords_private_key_t **key);

/**
 * @brief Free a public key
 * 
 * @param key The public key to free
 */
void echords_free_public_key(echords_public_key_t *key);

/**
 * @brief Free a private key
 * 
 * @param key The private key to free
 */
void echords_free_private_key(echords_private_key_t *key);

/**
 * @brief Encrypt data using RSA public key
 * 
 * @param key The public key to use for encryption
 * @param data The data to encrypt
 * @param data_len Length of the data
 * @param encrypted_data Buffer to store the encrypted data
 * @param encrypted_data_len Pointer to store the length of the encrypted data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_encrypt(echords_public_key_t *key, 
                               const uint8_t *data, 
                               size_t data_len,
                               uint8_t *encrypted_data, 
                               size_t *encrypted_data_len);

/**
 * @brief Decrypt data using RSA private key
 * 
 * @param key The private key to use for decryption
 * @param encrypted_data The encrypted data
 * @param encrypted_data_len Length of the encrypted data
 * @param decrypted_data Buffer to store the decrypted data
 * @param decrypted_data_len Pointer to store the length of the decrypted data
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_decrypt(echords_private_key_t *key, 
                               const uint8_t *encrypted_data, 
                               size_t encrypted_data_len,
                               uint8_t *decrypted_data, 
                               size_t *decrypted_data_len);

/**
 * @brief Sign data using RSA private key
 * 
 * @param key The private key to use for signing
 * @param data The data to sign
 * @param data_len Length of the data
 * @param signature Buffer to store the signature
 * @param signature_len Pointer to store the length of the signature
 * @return ECHORDS_SUCCESS on success, error code otherwise
 */
echords_error_t echords_sign(echords_private_key_t *key, 
                            const uint8_t *data, 
                            size_t data_len,
                            uint8_t *signature, 
                            size_t *signature_len);

/**
 * @brief Verify a signature using RSA public key
 * 
 * @param key The public key to use for verification
 * @param data The data that was signed
 * @param data_len Length of the data
 * @param signature The signature to verify
 * @param signature_len Length of the signature
 * @return ECHORDS_SUCCESS if signature is valid, error code otherwise
 */
echords_error_t echords_verify(echords_public_key_t *key, 
                              const uint8_t *data, 
                              size_t data_len,
                              const uint8_t *signature, 
                              size_t signature_len);

#endif /* ECHORDS_CRYPTO_H */
