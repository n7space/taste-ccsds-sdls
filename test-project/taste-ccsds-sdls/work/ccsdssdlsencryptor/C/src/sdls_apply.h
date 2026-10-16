/* SPDX-License-Identifier: Apache-2.0
 *
 * ApplySecurity, ported from the astro Go reference implementation
 * (pkg/sdls/apply.go).
 */
#ifndef SDLS_APPLY_H
#define SDLS_APPLY_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"
#include "sdls_sa.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Protects one frame data field and writes the bytes to place in the
 * carrier frame to out:
 *
 *   Security Header || data (ciphertext or plaintext) || Security Trailer
 *
 * frame_header is the carrier frame's own bytes, from the first octet of the
 * Transfer Frame Primary Header up to where the Security Header begins.
 * SDLS authenticates those octets without encrypting them, subject to the
 * SA's authentication bit mask. Pass frame_header_len == 0 (frame_header may
 * be NULL) to authenticate the security header and data alone.
 *
 * plaintext is the Transfer Frame Data Field to protect.
 *
 * The SA advances its IV counter on every successful call and refuses to
 * reuse one, returning SDLS_ERR_IV_EXHAUSTED when the counter space runs
 * out.
 *
 * This library does not perform block padding: GCM is a stream mode and
 * needs none (clause E1.2 note 2). The Pad Length field, if the SA declares
 * one, is transmitted as zeros.
 *
 * out must be at least SDLS_MAX_PROTECTED_SIZE octets, or sized precisely as
 * sdls_field_lengths_header_size(&sa->field_lengths) + plaintext_len +
 * sa->field_lengths.mac. *out_len receives the number of octets written.
 * frame_header_len must not exceed SDLS_MAX_FRAME_HEADER_SIZE and
 * plaintext_len must not exceed SDLS_MAX_DATA_SIZE. */
sdls_status_t sdls_apply_security(sdls_security_association_t *sa,
                                   const uint8_t *frame_header, size_t frame_header_len,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_APPLY_H */
