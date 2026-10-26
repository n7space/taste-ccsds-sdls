/* SPDX-License-Identifier: Apache-2.0
 *
 * Baseline authentication bit mask constructors, ported from the astro Go
 * reference implementation (pkg/sdls/mask.go).
 *
 * Clause 4.2.2.6.2 of CCSDS 355.0-B-2 sets per-frame-type rules for the
 * authentication bit mask: some header fields must be covered (the Virtual
 * Channel ID, the Security Header, the USLP MAP ID, the TC Segment Header)
 * and some must not be, because they change legitimately between the sender
 * applying security and the receiver checking it. The mandatory exclusions
 * are:
 *
 *   - the TM Master Channel Frame Count, rewritten when frames from several
 *     virtual channels are multiplexed onto a master channel;
 *   - the AOS Frame Header Error Control, computed downstream of security;
 *   - the Insert Zone of AOS and USLP frames, which is not secured;
 *   - the Initialization Vector inside the Security Header (clause
 *     4.2.2.6.2 h).
 *
 * Each constructor here fills the strictest mask that honours those
 * exclusions for one frame type: every other header octet is covered with
 * ones. Missions that want to exclude more (clause 4.2.2.6.2 permits leaving
 * unspecified fields out) can clear further octets in the returned buffer
 * afterward.
 *
 * out must be at least sdls_field_lengths_header_size(fl) plus the frame
 * header length (as documented per constructor) octets; *out_len receives
 * the number of octets written. All constructors return
 * SDLS_ERR_BUFFER_TOO_SMALL if out_cap is insufficient.
 */
#ifndef SDLS_MASK_H
#define SDLS_MASK_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"
#include "sdls_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TM Transfer Frame Primary Header width, CCSDS 132.0-B clause 4.1.2. */
#define SDLS_TM_PRIMARY_HEADER_SIZE 6
/* TC Transfer Frame Primary Header width, CCSDS 232.0-B clause 4.1.2. */
#define SDLS_TC_PRIMARY_HEADER_SIZE 5
/* Optional TC Segment Header width, CCSDS 232.0-B clause 4.1.3.2. */
#define SDLS_TC_SEGMENT_HEADER_SIZE 1
/* AOS Transfer Frame Primary Header width without the optional Frame Header
 * Error Control, CCSDS 732.0-B clause 4.1.2. */
#define SDLS_AOS_PRIMARY_HEADER_SIZE 6
/* Optional AOS Frame Header Error Control width, CCSDS 732.0-B clause
 * 4.1.2.6. */
#define SDLS_AOS_FHEC_SIZE 2

/* Builds the clause 4.2.2.6.2 authentication bit mask for a TM Transfer
 * Frame whose header is the 6-octet primary header followed by
 * secondary_header_len octets of Frame Secondary Header (zero when absent).
 * Clears the Master Channel Frame Count and the Security Header's IV. */
sdls_status_t sdls_mask_baseline_tm(size_t secondary_header_len,
                                    const sdls_field_lengths_t *fl,
                                    uint8_t *out, size_t out_cap, size_t *out_len);

/* Builds the clause 4.2.2.6.2 authentication bit mask for a TC Transfer
 * Frame: the 5-octet primary header, plus the 1-octet Segment Header when
 * has_segment_header is set. */
sdls_status_t sdls_mask_baseline_tc(int has_segment_header,
                                    const sdls_field_lengths_t *fl,
                                    uint8_t *out, size_t out_cap, size_t *out_len);

/* Builds the clause 4.2.2.6.2 authentication bit mask for an AOS Transfer
 * Frame: the 6-octet primary header, the 2-octet Frame Header Error Control
 * when has_fhec is set, and insert_zone_len octets of Insert Zone (zero when
 * absent). Clears the FHEC and Insert Zone. */
sdls_status_t sdls_mask_baseline_aos(int has_fhec, size_t insert_zone_len,
                                     const sdls_field_lengths_t *fl,
                                     uint8_t *out, size_t out_cap, size_t *out_len);

/* Builds the clause 4.2.2.6.2 authentication bit mask for a USLP Transfer
 * Frame whose primary header (variable, 4 to 14 octets) is
 * primary_header_len octets, followed by insert_zone_len octets of Insert
 * Zone (zero when absent). Clears the Insert Zone. */
sdls_status_t sdls_mask_baseline_uslp(size_t primary_header_len, size_t insert_zone_len,
                                      const sdls_field_lengths_t *fl,
                                      uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_MASK_H */
