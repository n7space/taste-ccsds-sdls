/* SPDX-License-Identifier: Apache-2.0 */
#include "sdls_types.h"

size_t sdls_field_lengths_header_size(const sdls_field_lengths_t *fl) {
    return (size_t)SDLS_SPI_SIZE + (size_t)fl->iv + (size_t)fl->seq_num + (size_t)fl->pad_len;
}

sdls_status_t sdls_field_lengths_validate(const sdls_field_lengths_t *fl) {
    if (fl->iv < 0 || fl->seq_num < 0 || fl->pad_len < 0 || fl->mac < 0) {
        return SDLS_ERR_INVALID_FIELD_LENGTHS;
    }
    if ((size_t)fl->iv > SDLS_MAX_IV_SIZE || (size_t)fl->seq_num > SDLS_MAX_SEQNUM_SIZE ||
        (size_t)fl->pad_len > SDLS_MAX_PADLEN_SIZE || (size_t)fl->mac > SDLS_MAX_MAC_SIZE) {
        return SDLS_ERR_INVALID_FIELD_LENGTHS;
    }
    if (sdls_field_lengths_header_size(fl) > SDLS_MAX_SECURITY_HEADER_SIZE) {
        return SDLS_ERR_HEADER_TOO_LONG;
    }
    return SDLS_OK;
}

unsigned sdls_security_header_pad_count(const sdls_security_header_t *h) {
    unsigned n = 0;
    for (int i = 0; i < h->fl.pad_len; i++) {
        n = (n << 8) | h->pad_length[i];
    }
    return n;
}
