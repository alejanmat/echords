/**
 * @file crypto.c
 * @brief Implementation of cryptographic functions for EchoRDS
 * 
 * This file implements the cryptographic functions used in the EchoRDS system,
 * including RSA encryption/decryption and key management.
 * 
 * @author Matias Alejandro Plumari
 * @version 0.1.0
 * @date 2025-06-04
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../include/echords.h"
#include "../include/crypto.h"

/**
 * @brief Structure for RSA public key
 */
struct echords_public_key_t {
    EVP_PKEY *key;  /**< OpenSSL EVP_PKEY structure */
};

/**
 * @brief Structure for RSA private key
 */
struct echords_private_key_t {
    EVP_PKEY *key;  /**< OpenSSL EVP_PKEY structure */
};

/**
 * @brief Generate an RSA key pair
 */
echords_error_t echords_generate_key_pair(const char *public_key_path, 
                                         const char *private_key_path, 
                                         int key_bits) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    FILE *fp = NULL;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Create the context for key generation
    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Initialize the key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Set the RSA key bits
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Generate the key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Save the private key
    if ((fp = fopen(private_key_path, "w")) == NULL) {
        result = ECHORDS_ERROR_IO;
        goto cleanup;
    }
    
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        result = ECHORDS_ERROR_CRYPTO;
        fclose(fp);
        goto cleanup;
    }
    
    fclose(fp);
    
    // Save the public key
    if ((fp = fopen(public_key_path, "w")) == NULL) {
        result = ECHORDS_ERROR_IO;
        goto cleanup;
    }
    
    if (!PEM_write_PUBKEY(fp, pkey)) {
        result = ECHORDS_ERROR_CRYPTO;
        fclose(fp);
        goto cleanup;
    }
    
    fclose(fp);
    
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    
    return result;
}

/**
 * @brief Load a public key from a file
 */
echords_error_t echords_load_public_key(const char *path, echords_public_key_t **key) {
    FILE *fp = NULL;
    echords_public_key_t *new_key = NULL;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Allocate memory for the key structure
    new_key = (echords_public_key_t *)malloc(sizeof(echords_public_key_t));
    if (!new_key) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Initialize the key
    new_key->key = NULL;
    
    // Open the key file
    fp = fopen(path, "r");
    if (!fp) {
        result = ECHORDS_ERROR_IO;
        goto cleanup;
    }
    
    // Read the public key
    new_key->key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (!new_key->key) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    fclose(fp);
    *key = new_key;
    return ECHORDS_SUCCESS;
    
cleanup:
    if (fp) fclose(fp);
    echords_free_public_key(new_key);
    return result;
}

/**
 * @brief Load a private key from a file
 */
echords_error_t echords_load_private_key(const char *path, echords_private_key_t **key) {
    FILE *fp = NULL;
    echords_private_key_t *new_key = NULL;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Allocate memory for the key structure
    new_key = (echords_private_key_t *)malloc(sizeof(echords_private_key_t));
    if (!new_key) {
        return ECHORDS_ERROR_MEMORY;
    }
    
    // Initialize the key
    new_key->key = NULL;
    
    // Open the key file
    fp = fopen(path, "r");
    if (!fp) {
        result = ECHORDS_ERROR_IO;
        goto cleanup;
    }
    
    // Read the private key
    new_key->key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!new_key->key) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    fclose(fp);
    *key = new_key;
    return ECHORDS_SUCCESS;
    
cleanup:
    if (fp) fclose(fp);
    echords_free_private_key(new_key);
    return result;
}

/**
 * @brief Free a public key
 */
void echords_free_public_key(echords_public_key_t *key) {
    if (key) {
        if (key->key) EVP_PKEY_free(key->key);
        free(key);
    }
}

/**
 * @brief Free a private key
 */
void echords_free_private_key(echords_private_key_t *key) {
    if (key) {
        if (key->key) EVP_PKEY_free(key->key);
        free(key);
    }
}

/**
 * @brief Encrypt data using RSA public key
 */
echords_error_t echords_encrypt(echords_public_key_t *key, 
                               const uint8_t *data, 
                               size_t data_len,
                               uint8_t *encrypted_data, 
                               size_t *encrypted_data_len) {
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Create encryption context
    ctx = EVP_PKEY_CTX_new(key->key, NULL);
    if (!ctx) {
        return ECHORDS_ERROR_CRYPTO;
    }
    
    // Initialize encryption operation
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Set padding mode
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Determine buffer length
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data, data_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Check if output buffer is large enough
    if (outlen > *encrypted_data_len) {
        *encrypted_data_len = outlen;
        result = ECHORDS_ERROR_MEMORY;
        goto cleanup;
    }
    
    // Encrypt data
    if (EVP_PKEY_encrypt(ctx, encrypted_data, encrypted_data_len, data, data_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return result;
}

/**
 * @brief Decrypt data using RSA private key
 */
echords_error_t echords_decrypt(echords_private_key_t *key, 
                               const uint8_t *encrypted_data, 
                               size_t encrypted_data_len,
                               uint8_t *decrypted_data, 
                               size_t *decrypted_data_len) {
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Create decryption context
    ctx = EVP_PKEY_CTX_new(key->key, NULL);
    if (!ctx) {
        return ECHORDS_ERROR_CRYPTO;
    }
    
    // Initialize decryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Set padding mode
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Determine buffer length
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_data, encrypted_data_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Check if output buffer is large enough
    if (outlen > *decrypted_data_len) {
        *decrypted_data_len = outlen;
        result = ECHORDS_ERROR_MEMORY;
        goto cleanup;
    }
    
    // Decrypt data
    if (EVP_PKEY_decrypt(ctx, decrypted_data, decrypted_data_len, encrypted_data, encrypted_data_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return result;
}

/**
 * @brief Sign data using RSA private key
 */
echords_error_t echords_sign(echords_private_key_t *key, 
                            const uint8_t *data, 
                            size_t data_len,
                            uint8_t *signature, 
                            size_t *signature_len) {
    EVP_MD_CTX *md_ctx = NULL;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Create message digest context
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return ECHORDS_ERROR_CRYPTO;
    }
    
    // Initialize signing operation
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key->key) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Add data to be signed
    if (EVP_DigestSignUpdate(md_ctx, data, data_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Determine signature length
    if (EVP_DigestSignFinal(md_ctx, NULL, signature_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Allocate memory for signature if needed
    if (!signature) {
        result = ECHORDS_SUCCESS;
        goto cleanup;
    }
    
    // Get signature
    if (EVP_DigestSignFinal(md_ctx, signature, signature_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    return result;
}

/**
 * @brief Verify a signature using RSA public key
 */
echords_error_t echords_verify(echords_public_key_t *key, 
                              const uint8_t *data, 
                              size_t data_len,
                              const uint8_t *signature, 
                              size_t signature_len) {
    EVP_MD_CTX *md_ctx = NULL;
    echords_error_t result = ECHORDS_SUCCESS;
    
    // Create message digest context
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return ECHORDS_ERROR_CRYPTO;
    }
    
    // Initialize verification operation
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, key->key) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Add data to be verified
    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
    // Verify signature
    if (EVP_DigestVerifyFinal(md_ctx, signature, signature_len) <= 0) {
        result = ECHORDS_ERROR_CRYPTO;
        goto cleanup;
    }
    
cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    return result;
}
