/* SPDX-License-Identifier: Apache-2.0
 *
 * AES-256-GCM (NIST SP 800-38D), built on top of the registered AES-256
 * single-block encryption callback (sdls_crypto.h). Implements the GHASH
 * and CTR constructions this library needs for the CCSDS 355.0-B-2 clause
 * E1/E3/E4 authenticated encryption baseline and its GMAC authentication
 * companion. Not part of the public API: sdls_apply.c and sdls_process.c
 * are the only callers.
 *
 * The IV is always exactly SDLS_GCM_IV_SIZE (96 bits), matching the CCSDS
 * baseline, so this implementation only needs the "96-bit IV" special case
 * of the spec's J0 construction (SP 800-38D clause 7.1): J0 = IV || 0^31 1.
 */
#ifndef SDLS_INTERNAL_GCM_H
#define SDLS_INTERNAL_GCM_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"
#include "sdls_types.h"

/* Encrypts plaintext (plaintext_len octets, may be 0 for a GMAC-style
 * authentication-only call) with AES-256-GCM under key and the 96-bit iv,
 * authenticating aad (aad_len octets). Writes plaintext_len octets of
 * ciphertext to out_ciphertext and tag_size octets of tag to out_tag (the
 * leading tag_size octets of the full 128-bit tag, matching the
 * most-significant-bits-first truncation of NIST SP 800-38D clause 5.2.1.2
 * and Go's crypto/cipher.NewGCMWithTagSize).
 *
 * out_ciphertext may be NULL iff plaintext_len == 0. tag_size must be
 * between SDLS_MIN_MAC_SIZE and SDLS_MAX_MAC_SIZE. */
sdls_status_t sdls_gcm_seal(const uint8_t key[SDLS_AES_KEY_SIZE],
                            const uint8_t iv[SDLS_GCM_IV_SIZE],
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            size_t tag_size,
                            uint8_t *out_ciphertext, uint8_t *out_tag);

/* Decrypts and verifies a message sealed with sdls_gcm_seal(). ciphertext is
 * ciphertext_len octets (0 for a GMAC-style call), tag is the tag_size-octet
 * truncated tag. On success writes ciphertext_len octets of recovered
 * plaintext to out_plaintext and returns SDLS_OK. On tag mismatch returns
 * SDLS_ERR_AUTHENTICATION_FAILED and writes nothing to out_plaintext.
 *
 * out_plaintext may be NULL iff ciphertext_len == 0. */
sdls_status_t sdls_gcm_open(const uint8_t key[SDLS_AES_KEY_SIZE],
                            const uint8_t iv[SDLS_GCM_IV_SIZE],
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *tag, size_t tag_size,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *out_plaintext);

/* Encrypts or decrypts len octets of in with the AES-256-GCM keystream for
 * the 96-bit iv (GCTR starting at inc32(J0), NIST SP 800-38D clause 7.1),
 * without computing or checking any tag. The output is exactly the
 * ciphertext sdls_gcm_seal() would produce, i.e. AES-256-CTR. Used by the
 * encryption-only service (SDLS_MODE_ENCRYPTION). in and out may alias.
 * Not part of the astro Go reference. */
sdls_status_t sdls_gcm_ctr_crypt(const uint8_t key[SDLS_AES_KEY_SIZE],
                                 const uint8_t iv[SDLS_GCM_IV_SIZE],
                                 const uint8_t *in, size_t len, uint8_t *out);

#endif /* SDLS_INTERNAL_GCM_H */
