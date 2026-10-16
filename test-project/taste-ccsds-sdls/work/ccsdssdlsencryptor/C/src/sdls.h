/* SPDX-License-Identifier: Apache-2.0
 *
 * sdls -- CCSDS 355.0-B-2 Space Data Link Security Protocol, in C.
 *
 * Provides the clause E1/E3/E4 AES-256-GCM authenticated encryption
 * baseline, its GMAC authentication-only companion, and the clause E2
 * AES-CMAC telecommand authentication baseline. Ported from the astro Go
 * reference implementation (github.com/ravisuhag/astro, pkg/sdls).
 *
 * This library performs no dynamic memory allocation and contains no AES or
 * CMAC implementation of its own: register an AES-256 single-block encrypt
 * callback and an AES-CMAC-256 callback with sdls_crypto_set_backend()
 * (see sdls_crypto.h) before protecting or verifying any frame.
 *
 *                   +-------------- carrier frame data field --------------+
 *  frame header ... | Security Header | data (or ciphertext) | Trailer     |
 *                   +-------------------------------------------------------+
 *
 * Typical usage:
 *
 *   sdls_crypto_backend_t backend = { my_aes256_encrypt_block, my_cmac256, NULL };
 *   sdls_crypto_set_backend(&backend);
 *
 *   sdls_security_association_t sa = {
 *       .spi = 1,
 *       .mode = SDLS_MODE_AUTHENTICATED_ENCRYPTION,
 *       .field_lengths = { .iv = SDLS_GCM_IV_SIZE, .mac = 16 },
 *       .seq_window = 100,
 *   };
 *   memcpy(sa.key, my_key, SDLS_AES_KEY_SIZE);
 *
 *   uint8_t out[SDLS_MAX_PROTECTED_SIZE];
 *   size_t out_len;
 *   sdls_apply_security(&sa, frame_header, frame_header_len,
 *                        plaintext, plaintext_len, out, sizeof(out), &out_len);
 */
#ifndef SDLS_H
#define SDLS_H

#include "sdls_apply.h"
#include "sdls_channel.h"
#include "sdls_crypto.h"
#include "sdls_errors.h"
#include "sdls_header.h"
#include "sdls_mask.h"
#include "sdls_process.h"
#include "sdls_sa.h"
#include "sdls_types.h"

#endif /* SDLS_H */
