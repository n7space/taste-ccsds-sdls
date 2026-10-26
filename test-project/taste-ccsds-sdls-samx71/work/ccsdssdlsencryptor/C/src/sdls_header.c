/* SPDX-License-Identifier: Apache-2.0
 *
 * Ported from the astro Go reference implementation (pkg/sdls/header.go).
 */
#include "sdls_header.h"

#include <string.h>

sdls_status_t sdls_header_encode(const sdls_security_header_t *h,
                                  uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t size = sdls_field_lengths_header_size(&h->fl);
    if (size > SDLS_MAX_SECURITY_HEADER_SIZE) {
        return SDLS_ERR_HEADER_TOO_LONG;
    }
    if (out_cap < size) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }

    size_t off = 0;
    out[off++] = (uint8_t)(h->spi >> 8);
    out[off++] = (uint8_t)(h->spi & 0xFF);

    memcpy(out + off, h->iv, (size_t)h->fl.iv);
    off += (size_t)h->fl.iv;
    memcpy(out + off, h->seq_num, (size_t)h->fl.seq_num);
    off += (size_t)h->fl.seq_num;
    memcpy(out + off, h->pad_length, (size_t)h->fl.pad_len);
    off += (size_t)h->fl.pad_len;

    *out_len = off;
    return SDLS_OK;
}

sdls_status_t sdls_header_decode(const uint8_t *data, size_t data_len,
                                  const sdls_field_lengths_t *fl,
                                  sdls_security_header_t *h, size_t *consumed) {
    sdls_status_t st = sdls_field_lengths_validate(fl);
    if (st != SDLS_OK) {
        return st;
    }
    size_t size = sdls_field_lengths_header_size(fl);
    if (data_len < size) {
        return SDLS_ERR_DATA_TOO_SHORT;
    }

    memset(h, 0, sizeof(*h));
    h->fl = *fl;
    h->spi = (uint16_t)(((uint16_t)data[0] << 8) | data[1]);

    size_t off = SDLS_SPI_SIZE;
    memcpy(h->iv, data + off, (size_t)fl->iv);
    off += (size_t)fl->iv;
    memcpy(h->seq_num, data + off, (size_t)fl->seq_num);
    off += (size_t)fl->seq_num;
    memcpy(h->pad_length, data + off, (size_t)fl->pad_len);
    off += (size_t)fl->pad_len;

    *consumed = off;
    return SDLS_OK;
}
