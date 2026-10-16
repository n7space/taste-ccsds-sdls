/* SPDX-License-Identifier: Apache-2.0
 *
 * Registrable cryptographic backend for the SDLS library.
 *
 * This library implements CCSDS 355.0-B-2 itself (Security Header framing,
 * GCM/GMAC and CMAC constructions, masking, anti-replay, mode dispatch) but
 * contains no AES or CMAC implementation of its own. Two primitives must be
 * supplied by the application, typically backed by a hardware crypto engine
 * or a library such as OpenSSL or mbedTLS:
 *
 *   1. AES-256 single-block encryption (ECB, one 16-octet block). This
 *      library builds its own AES-256-GCM (CTR keystream + GHASH) on top of
 *      it, per NIST SP 800-38D, matching the clause E1/E3/E4 baseline.
 *
 *   2. AES-CMAC-256 (SP 800-38B / RFC 4493), producing the full 128-bit tag
 *      over an arbitrary-length message. This library truncates the tag to
 *      the SA's configured width itself; it does not derive CMAC subkeys or
 *      run the CBC-MAC construction.
 *
 * Register both callbacks once, before calling any sdls_apply_security() or
 * sdls_process_security(), with sdls_crypto_set_backend().
 */
#ifndef SDLS_CRYPTO_H
#define SDLS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Encrypts exactly one 16-octet block with AES-256 in ECB mode:
 * out_block = AES-256-Encrypt(key, in_block).
 *
 * key is exactly SDLS_AES_KEY_SIZE (32) octets. in_block and out_block are
 * exactly 16 octets each and may alias. Return 0 on success, nonzero on
 * failure (surfaced as SDLS_ERR_CRYPTO_BACKEND_FAILED). */
typedef int (*sdls_aes256_encrypt_block_fn)(void *user_ctx,
                                             const uint8_t key[SDLS_AES_KEY_SIZE],
                                             const uint8_t in_block[16],
                                             uint8_t out_block[16]);

/* Computes the full 128-bit AES-CMAC-256 tag over data:
 * mac_out = AES-CMAC-256(key, data, data_len).
 *
 * key is exactly SDLS_AES_KEY_SIZE (32) octets. mac_out receives exactly 16
 * octets; this library truncates it to the SA's configured MAC width itself.
 * Return 0 on success, nonzero on failure. */
typedef int (*sdls_cmac256_fn)(void *user_ctx,
                                const uint8_t key[SDLS_AES_KEY_SIZE],
                                const uint8_t *data, size_t data_len,
                                uint8_t mac_out[16]);

/* A registrable set of cryptographic primitives. Either function pointer may
 * be NULL if the caller never exercises the code path that needs it (e.g. an
 * SA that only ever uses CMAC never calls aes256_encrypt_block), but calling
 * sdls_apply_security()/sdls_process_security() on an SA that needs a
 * function which is NULL returns SDLS_ERR_NO_CRYPTO_BACKEND. */
typedef struct sdls_crypto_backend {
    sdls_aes256_encrypt_block_fn aes256_encrypt_block;
    sdls_cmac256_fn              cmac256;
    void *user_ctx;
} sdls_crypto_backend_t;

/* Registers the process-wide cryptographic backend. Not thread-safe with
 * concurrent sdls_apply_security()/sdls_process_security() calls; register
 * once at startup before using any Security Association. */
void sdls_crypto_set_backend(const sdls_crypto_backend_t *backend);

/* Returns the currently registered backend, or a zeroed structure (both
 * function pointers NULL) if none has been registered. */
const sdls_crypto_backend_t *sdls_crypto_get_backend(void);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_CRYPTO_H */
