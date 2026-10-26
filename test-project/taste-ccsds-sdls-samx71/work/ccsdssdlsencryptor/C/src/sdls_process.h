/* SPDX-License-Identifier: Apache-2.0
 *
 * ProcessSecurity, ported from the astro Go reference implementation
 * (pkg/sdls/process.go).
 */
#ifndef SDLS_PROCESS_H
#define SDLS_PROCESS_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_channel.h"
#include "sdls_errors.h"
#include "sdls_sa.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Resolves a Security Parameter Index to the Security Association
 * registered for it. Implementations should return SDLS_ERR_UNKNOWN_SPI when
 * the index is not configured. */
typedef sdls_status_t (*sdls_sa_lookup_fn)(void *user_ctx, uint16_t spi,
                                           sdls_security_association_t **sa_out);

/* Maximum number of Security Associations a single sdls_static_lookup_t can
 * index. */
#ifndef SDLS_MAX_LOOKUP_ENTRIES
#define SDLS_MAX_LOOKUP_ENTRIES 16
#endif

/* A fixed-capacity SALookup over a static set of Security Associations,
 * keyed by their SPI -- the common case of SAs preloaded before a mission
 * starts (clause 2.3.1.5). This is the fixed-size equivalent of the Go
 * reference's StaticLookup, which used a map; here the SA pointers are
 * supplied by the caller and stored by reference (no copies, no
 * allocation). */
typedef struct sdls_static_lookup {
    sdls_security_association_t *sas[SDLS_MAX_LOOKUP_ENTRIES];
    size_t count;
} sdls_static_lookup_t;

/* Initializes a static lookup table over sas[0..count). count must not
 * exceed SDLS_MAX_LOOKUP_ENTRIES. */
sdls_status_t sdls_static_lookup_init(sdls_static_lookup_t *lookup,
                                      sdls_security_association_t **sas, size_t count);

/* An sdls_sa_lookup_fn implementation backed by a sdls_static_lookup_t;
 * pass the table as user_ctx. */
sdls_status_t sdls_static_lookup_fn(void *user_ctx, uint16_t spi,
                                    sdls_security_association_t **sa_out);

/* Reverses sdls_apply_security, per CCSDS 355.0-B-2 clause 4.2.4.
 *
 * data_field is the carrier frame's data field: Security Header, then the
 * protected data, then the Security Trailer. frame_header is the same
 * header prefix the sender authenticated. lookup/lookup_ctx resolve the SPI
 * to its SA.
 *
 * On success, *header_out is filled with the decoded Security Header and
 * plaintext_out/plaintext_len receive the recovered Transfer Frame Data
 * Field. On any verification failure this returns a nonzero status and
 * writes nothing to plaintext_out: no partial plaintext ever escapes
 * (clause 4.2.4.2.3).
 *
 * This only verifies the SPI. It has no way to know which channel the frame
 * arrived on, so the clause 4.2.4.3 check that the SA is the one agreed for
 * that channel is left to the caller. Use sdls_process_security_for_channel
 * to have this enforced. */
sdls_status_t sdls_process_security(const uint8_t *data_field, size_t data_field_len,
                                     const uint8_t *frame_header, size_t frame_header_len,
                                     sdls_sa_lookup_fn lookup, void *lookup_ctx,
                                     sdls_security_header_t *header_out,
                                     uint8_t *plaintext_out, size_t plaintext_cap,
                                     size_t *plaintext_len);

/* sdls_process_security with the receiving channel in hand: ch identifies
 * the Global Virtual Channel (or Global MAP) the frame arrived on. When the
 * SA that the SPI names declares a channel binding in its channels list, the
 * frame is rejected with SDLS_ERR_SA_CHANNEL_MISMATCH unless ch is in that
 * list (clause 4.2.4.3) before any cryptographic work. An SA with an empty
 * channels list accepts any channel. */
sdls_status_t sdls_process_security_for_channel(const uint8_t *data_field, size_t data_field_len,
                                                 const uint8_t *frame_header, size_t frame_header_len,
                                                 const sdls_channel_id_t *ch,
                                                 sdls_sa_lookup_fn lookup, void *lookup_ctx,
                                                 sdls_security_header_t *header_out,
                                                 uint8_t *plaintext_out, size_t plaintext_cap,
                                                 size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_PROCESS_H */
