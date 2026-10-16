/* SPDX-License-Identifier: Apache-2.0
 *
 * Private Security Association helpers shared by sdls_sa.c, sdls_apply.c
 * and sdls_process.c. Ported from the unexported methods of the astro Go
 * reference implementation's SecurityAssociation (pkg/sdls/sa.go,
 * pkg/sdls/apply.go, pkg/sdls/process.go). Not part of the public API.
 */
#ifndef SDLS_INTERNAL_SA_H
#define SDLS_INTERNAL_SA_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"
#include "sdls_sa.h"
#include "sdls_types.h"

/* Reports whether this SA authenticates with AES-CMAC rather than GMAC.
 * Only meaningful for SDLS_MODE_AUTHENTICATION; authenticated encryption is
 * always AES-GCM. */
int sdls_sa__uses_cmac(const sdls_security_association_t *sa);

/* Reports whether the IV doubles as the anti-replay counter (clause
 * 4.1.1.4.2), which the clause E1 baseline takes: the Sequence Number field
 * is zero octets wide. */
int sdls_sa__uses_iv_as_sequence(const sdls_security_association_t *sa);

/* Reports whether this SA's service type produces a Security Trailer. */
int sdls_sa__needs_mac(const sdls_security_association_t *sa);

/* Advances the sender's IV counter and writes the value to transmit to
 * iv_out (capacity SDLS_MAX_IV_SIZE); *iv_len receives sa->field_lengths.iv
 * (0 when the SA carries no IV field). Returns SDLS_ERR_IV_EXHAUSTED rather
 * than wrapping. */
sdls_status_t sdls_sa__next_iv(sdls_security_association_t *sa, uint8_t *iv_out, size_t *iv_len);

/* Advances the sender's explicit sequence number, clause 4.2.3.4 a). Writes
 * to seq_out (capacity SDLS_MAX_SEQNUM_SIZE); *seq_len receives
 * sa->field_lengths.seq_num (0 when the SA carries no Sequence Number
 * field). */
sdls_status_t sdls_sa__next_seq(sdls_security_association_t *sa, uint8_t *seq_out, size_t *seq_len);

/* Applies the anti-replay rules of clause 2.3.2.3 to a received counter
 * (received, received_len octets: the IV or the Sequence Number, whichever
 * this SA uses). Must run only after the MAC has verified, so a forged
 * frame cannot advance the window (clause 4.2.4.4). */
sdls_status_t sdls_sa__check_and_advance_sequence(sdls_security_association_t *sa,
                                                   const uint8_t *received, size_t received_len);

/* Produces the masked authenticated data that precedes the frame data field,
 * per clause 4.2.3.4 d): frame_header || security_header, with sa->auth_mask
 * applied by bitwise AND, and the Initialization Vector position always
 * zeroed regardless of the mask (clause 4.2.2.6.2 h)).
 *
 * out must be at least frame_header_len + header_bytes_len octets
 * (SDLS_MAX_FRAME_HEADER_SIZE + SDLS_MAX_SECURITY_HEADER_SIZE is always
 * sufficient); *out_len receives the number of octets written. */
sdls_status_t sdls_sa__build_auth_payload_prefix(const sdls_security_association_t *sa,
                                                  const uint8_t *frame_header, size_t frame_header_len,
                                                  const uint8_t *header_bytes, size_t header_bytes_len,
                                                  uint8_t *out, size_t out_cap, size_t *out_len);

/* Computes the AES-CMAC over the Authentication Payload (prefix || data),
 * per clause E2, truncated to sa->field_lengths.mac octets via the
 * registered CMAC callback. mac_out must be at least
 * sa->field_lengths.mac octets. */
sdls_status_t sdls_sa__cmac_tag(const sdls_security_association_t *sa,
                                 const uint8_t *prefix, size_t prefix_len,
                                 const uint8_t *data, size_t data_len,
                                 uint8_t *mac_out, size_t mac_cap, size_t *mac_len);

/* Runs the steps that follow a verified MAC: anti-replay (via
 * sdls_sa__check_and_advance_sequence), then Pad Length removal (clause
 * 4.2.3.3 b)). plaintext_len is updated in place to drop any trailing pad
 * octets the header declares. */
sdls_status_t sdls_sa__finish_processing(sdls_security_association_t *sa,
                                          const sdls_security_header_t *header,
                                          size_t *plaintext_len);

#endif /* SDLS_INTERNAL_SA_H */
