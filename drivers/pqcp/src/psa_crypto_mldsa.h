/* PSA driver for ML-DSA using mldsa-native */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PSA_CRYPTO_MLDSA_H
#define TF_PSA_CRYPTO_PSA_CRYPTO_MLDSA_H

#include <psa/crypto.h>

/** Export the public key of an ML-DSA key pair.
 *
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This must be a key pair
 *                              in the standard representation, i.e.
 *                              just the 32-byte seed.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param[out] data             On success, the exported key.
 * \param data_size             The size of \p data, in bytes.
 * \param[out] data_length      On success, the length of the data written
 *                              to \p data.
 *
 * \retval 0
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p data_size is too small.
 */
psa_status_t tf_psa_crypto_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length);

/** Sign a message using pure-ML-DSA (without pre-hashing).
 *
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This must be a key pair
 *                              in the standard representation, i.e.
 *                              just the 32-byte seed.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param alg                   The algorithm:
 *                              #PSA_ALG_ML_DSA (not implemented yet) or
 *                              #PSA_ALG_DETERMINISTIC_ML_DSA.
 * \param[in] message           The message to sign.
 * \param message_length        The length of \p message, in bytes.
 * \param[out] signature        On success, the exported key.
 * \param signature_size        The size of \p signature, in bytes.
 * \param[out] signature_length On success, the length of the data written
 *                              to \p signature.
 *
 * \retval 0
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported,
 *         or the algorithm is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid, or the key type is invalid for the
 *         given algorithm.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p signature_size is too small.
 */
psa_status_t tf_psa_crypto_mldsa_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

/** Verify a message using pure-ML-DSA (without pre-hashing).
 *
 * \param[in] attributes        The key attributes.
 * \param[in] key_buffer        The key material. This must be a public key
 *                              in the standard representation.
 * \param key_buffer_size       The size of \p key_buffer, in bytes.
 * \param alg                   The algorithm:
 *                              #PSA_ALG_ML_DSA (not implemented yet) or
 *                              #PSA_ALG_DETERMINISTIC_ML_DSA.
 * \param[in] message           The message to verify.
 * \param message_length        The length of \p message, in bytes.
 * \param[out] signature        The signature to verify.
 * \param signature_length      The length of \p signature, in bytes.
 *
 * \retval 0
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or size registered in \p attributes is not supported,
 *         or the algorithm is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key material is invalid.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The signature is not valid for this message.
 */
psa_status_t tf_psa_crypto_mldsa_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *message, size_t message_length,
    const uint8_t *signature, size_t signature_length);

#endif /* "psa_crypto_mldsa.h" */
