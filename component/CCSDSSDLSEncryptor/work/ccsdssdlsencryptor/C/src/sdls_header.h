/* SPDX-License-Identifier: Apache-2.0
 *
 * Security Header encode/decode, ported from the astro Go reference
 * implementation (pkg/sdls/header.go).
 */
#ifndef SDLS_HEADER_H
#define SDLS_HEADER_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"
#include "sdls_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Serializes the Security Header. Field widths come from h->fl. out must be
 * at least sdls_field_lengths_header_size(&h->fl) octets; *out_len receives
 * the number of octets written. */
sdls_status_t sdls_header_encode(const sdls_security_header_t *h,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

/* Parses a Security Header from the front of data using the field widths fl
 * names. *consumed receives the number of octets read (== 
 * sdls_field_lengths_header_size(fl) on success). The caller reads the SPI
 * first (always the leading 2 octets), looks up the SA, and passes that SA's
 * field_lengths here. */
sdls_status_t sdls_header_decode(const uint8_t *data, size_t data_len,
                                  const sdls_field_lengths_t *fl,
                                  sdls_security_header_t *h, size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_HEADER_H */
