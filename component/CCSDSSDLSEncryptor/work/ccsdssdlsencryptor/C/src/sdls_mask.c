/* SPDX-License-Identifier: Apache-2.0
 *
 * Ported from the astro Go reference implementation (pkg/sdls/mask.go).
 */
#include "sdls_mask.h"

#include <string.h>

/* Builds a mask of ones over frame_header_len octets of frame header plus
 * the security header described by fl, with the Initialization Vector
 * position cleared per clause 4.2.2.6.2 h). */
static sdls_status_t ones_mask(size_t frame_header_len, const sdls_field_lengths_t *fl,
                                uint8_t *out, size_t out_cap, size_t *out_len) {
    sdls_status_t st = sdls_field_lengths_validate(fl);
    if (st != SDLS_OK) {
        return st;
    }

    size_t header_size = sdls_field_lengths_header_size(fl);
    size_t total = frame_header_len + header_size;
    if (out_cap < total) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }

    memset(out, 0xFF, total);

    size_t iv_start = frame_header_len + SDLS_SPI_SIZE;
    for (size_t i = iv_start; i < iv_start + (size_t)fl->iv && i < total; i++) {
        out[i] = 0;
    }

    *out_len = total;
    return SDLS_OK;
}

/* Clears length octets of mask starting at offset. */
static void zero_range(uint8_t *mask, size_t mask_len, size_t offset, size_t length) {
    for (size_t i = offset; i < offset + length && i < mask_len; i++) {
        mask[i] = 0;
    }
}

sdls_status_t sdls_mask_baseline_tm(size_t secondary_header_len,
                                    const sdls_field_lengths_t *fl,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t frame_len = SDLS_TM_PRIMARY_HEADER_SIZE + secondary_header_len;
    sdls_status_t st = ones_mask(frame_len, fl, out, out_cap, out_len);
    if (st != SDLS_OK) {
        return st;
    }
    /* tmMCFCOffset: the Master Channel Frame Count sits at octet 2 of the
     * 6-octet TM primary header, always present regardless of the
     * secondary header. */
    out[2] = 0;
    return SDLS_OK;
}

sdls_status_t sdls_mask_baseline_tc(int has_segment_header,
                                    const sdls_field_lengths_t *fl,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t size = SDLS_TC_PRIMARY_HEADER_SIZE + (has_segment_header ? SDLS_TC_SEGMENT_HEADER_SIZE : 0);
    return ones_mask(size, fl, out, out_cap, out_len);
}

sdls_status_t sdls_mask_baseline_aos(int has_fhec, size_t insert_zone_len,
                                     const sdls_field_lengths_t *fl,
                                     uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t size = SDLS_AOS_PRIMARY_HEADER_SIZE;
    size_t fhec_start = size;
    if (has_fhec) {
        size += SDLS_AOS_FHEC_SIZE;
    }
    size_t insert_start = size;
    size += insert_zone_len;

    sdls_status_t st = ones_mask(size, fl, out, out_cap, out_len);
    if (st != SDLS_OK) {
        return st;
    }
    if (has_fhec) {
        zero_range(out, *out_len, fhec_start, SDLS_AOS_FHEC_SIZE);
    }
    zero_range(out, *out_len, insert_start, insert_zone_len);
    return SDLS_OK;
}

sdls_status_t sdls_mask_baseline_uslp(size_t primary_header_len, size_t insert_zone_len,
                                      const sdls_field_lengths_t *fl,
                                      uint8_t *out, size_t out_cap, size_t *out_len) {
    sdls_status_t st = ones_mask(primary_header_len + insert_zone_len, fl, out, out_cap, out_len);
    if (st != SDLS_OK) {
        return st;
    }
    zero_range(out, *out_len, primary_header_len, insert_zone_len);
    return SDLS_OK;
}
