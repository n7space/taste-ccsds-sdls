/* SPDX-License-Identifier: Apache-2.0
 *
 * Ported from the astro Go reference implementation (pkg/sdls/sa.go).
 */
#include "sdls_sa.h"

#include <string.h>

#include "sdls_crypto.h"
#include "sdls_sa_internal.h"
#include "sdls_util.h"

int sdls_sa__needs_mac(const sdls_security_association_t *sa) {
    return sa->mode == SDLS_MODE_AUTHENTICATION || sa->mode == SDLS_MODE_AUTHENTICATED_ENCRYPTION;
}

int sdls_sa__uses_cmac(const sdls_security_association_t *sa) {
    return sa->mode == SDLS_MODE_AUTHENTICATION && sa->auth_algorithm == SDLS_AUTH_CMAC;
}

int sdls_sa__uses_iv_as_sequence(const sdls_security_association_t *sa) {
    return sa->field_lengths.seq_num == 0 && sa->field_lengths.iv > 0;
}

sdls_status_t sdls_sa_validate(const sdls_security_association_t *sa) {
    if (sa->spi == SDLS_SPI_RESERVED_ZERO || sa->spi == SDLS_SPI_RESERVED_ALL_ONES) {
        return SDLS_ERR_INVALID_SPI;
    }

    switch (sa->mode) {
        case SDLS_MODE_AUTHENTICATION:
        case SDLS_MODE_ENCRYPTION:
        case SDLS_MODE_AUTHENTICATED_ENCRYPTION:
            break;
        default:
            return SDLS_ERR_INVALID_MODE;
    }

    sdls_status_t st = sdls_field_lengths_validate(&sa->field_lengths);
    if (st != SDLS_OK) {
        return st;
    }

    if (sdls_sa__needs_mac(sa)) {
        if (sdls_sa__uses_cmac(sa)) {
            /* Clause E2.2 note: CMAC needs no initialization vector. */
            if (sa->field_lengths.iv != 0) {
                return SDLS_ERR_INVALID_FIELD_LENGTHS;
            }
            if (sa->field_lengths.mac < SDLS_MIN_CMAC_SIZE || sa->field_lengths.mac > SDLS_MAX_MAC_SIZE) {
                return SDLS_ERR_INVALID_FIELD_LENGTHS;
            }
        } else {
            if (sa->field_lengths.iv != SDLS_GCM_IV_SIZE) {
                return SDLS_ERR_INVALID_FIELD_LENGTHS;
            }
            if (sa->field_lengths.mac < SDLS_MIN_MAC_SIZE || sa->field_lengths.mac > SDLS_MAX_MAC_SIZE) {
                return SDLS_ERR_INVALID_FIELD_LENGTHS;
            }
        }
    } else if (sa->mode == SDLS_MODE_ENCRYPTION) {
        /* Encryption only: AES-256 GCM keystream (CTR) under a 96-bit IV,
         * no Security Trailer. */
        if (sa->field_lengths.iv != SDLS_GCM_IV_SIZE || sa->field_lengths.mac != 0) {
            return SDLS_ERR_INVALID_FIELD_LENGTHS;
        }
    }

    /* An SA that asks for anti-replay protection but carries neither an IV
     * nor a Sequence Number field has nothing to check against. */
    if (sa->seq_window > 0 && sa->field_lengths.iv == 0 && sa->field_lengths.seq_num == 0) {
        return SDLS_ERR_NO_ANTI_REPLAY_COUNTER;
    }

    return SDLS_OK;
}

int sdls_sa_replay_protected(const sdls_security_association_t *sa) {
    return sa->seq_window > 0 && (sa->field_lengths.iv > 0 || sa->field_lengths.seq_num > 0);
}

sdls_status_t sdls_sa_iv_counter(const sdls_security_association_t *sa,
                                  uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!sa->iv_counter_initialized || sa->field_lengths.iv <= 0) {
        *out_len = 0;
        return SDLS_OK;
    }
    size_t n = (size_t)sa->field_lengths.iv;
    if (out_cap < n) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(out, sa->iv_counter, n);
    *out_len = n;
    return SDLS_OK;
}

sdls_status_t sdls_sa_set_iv_counter(sdls_security_association_t *sa,
                                      const uint8_t *v, size_t v_len) {
    if (v_len != (size_t)sa->field_lengths.iv) {
        return SDLS_ERR_INVALID_IV_COUNTER;
    }
    memcpy(sa->iv_counter, v, v_len);
    sa->iv_counter_initialized = 1;
    return SDLS_OK;
}

int sdls_sa_serves_channel(const sdls_security_association_t *sa, const sdls_channel_id_t *ch) {
    if (sa->channels_len == 0) {
        return 1;
    }
    for (size_t i = 0; i < sa->channels_len; i++) {
        if (sdls_channel_id_equal(&sa->channels[i], ch)) {
            return 1;
        }
    }
    return 0;
}

sdls_status_t sdls_sa__next_iv(sdls_security_association_t *sa, uint8_t *iv_out, size_t *iv_len) {
    size_t width = (size_t)sa->field_lengths.iv;
    if (width == 0) {
        *iv_len = 0;
        return SDLS_OK;
    }
    if (!sa->iv_counter_initialized) {
        /* The first frame transmits counter value 1, leaving 0 unused so a
         * freshly initialized receiver never accepts a replayed zero. */
        memset(sa->iv_counter, 0, sizeof(sa->iv_counter));
        sa->iv_counter_initialized = 1;
    }
    sdls_status_t st = sdls_be_increment(sa->iv_counter, width);
    if (st != SDLS_OK) {
        return st;
    }
    memcpy(iv_out, sa->iv_counter, width);
    *iv_len = width;
    return SDLS_OK;
}

sdls_status_t sdls_sa__next_seq(sdls_security_association_t *sa, uint8_t *seq_out, size_t *seq_len) {
    size_t width = (size_t)sa->field_lengths.seq_num;
    if (width == 0) {
        *seq_len = 0;
        return SDLS_OK;
    }
    if (!sa->seq_counter_initialized) {
        memset(sa->seq_counter, 0, sizeof(sa->seq_counter));
        sa->seq_counter_initialized = 1;
    }
    sdls_status_t st = sdls_be_increment(sa->seq_counter, width);
    if (st != SDLS_OK) {
        return st;
    }
    memcpy(seq_out, sa->seq_counter, width);
    *seq_len = width;
    return SDLS_OK;
}

sdls_status_t sdls_sa__check_and_advance_sequence(sdls_security_association_t *sa,
                                                   const uint8_t *received, size_t received_len) {
    if (sa->seq_window == 0 || received_len == 0) {
        return SDLS_OK;
    }

    if (sa->seq_seen) {
        /* Widths are fixed for the SA's lifetime, so a mismatch here would
         * indicate a caller error; treat it conservatively as a replay. */
        if (received_len != sa->last_seq_len) {
            return SDLS_ERR_REPLAY_DETECTED;
        }

        /* Clause 2.3.2.3.2: accept only a value higher than the stored one. */
        if (sdls_be_compare(received, sa->last_seq, received_len) <= 0) {
            return SDLS_ERR_REPLAY_DETECTED;
        }

        /* Clause 2.3.2.3.3: and no more than the window ahead of it. */
        uint8_t delta[SDLS_MAX_COUNTER_SIZE];
        sdls_be_subtract(received, sa->last_seq, received_len, delta);
        uint64_t delta_val;
        if (!sdls_be_to_u64(delta, received_len, &delta_val) || delta_val > sa->seq_window) {
            return SDLS_ERR_REPLAY_DETECTED;
        }
    }

    memcpy(sa->last_seq, received, received_len);
    sa->last_seq_len = received_len;
    sa->seq_seen = 1;
    return SDLS_OK;
}

sdls_status_t sdls_sa__build_auth_payload_prefix(const sdls_security_association_t *sa,
                                                  const uint8_t *frame_header, size_t frame_header_len,
                                                  const uint8_t *header_bytes, size_t header_bytes_len,
                                                  uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t total = frame_header_len + header_bytes_len;
    if (out_cap < total) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }

    if (frame_header_len > 0) {
        memcpy(out, frame_header, frame_header_len);
    }
    memcpy(out + frame_header_len, header_bytes, header_bytes_len);

    if (sa->auth_mask != NULL) {
        if (sa->auth_mask_len < total) {
            return SDLS_ERR_MASK_TOO_SHORT;
        }
        for (size_t i = 0; i < total; i++) {
            out[i] &= sa->auth_mask[i];
        }
    }

    /* Clause 4.2.2.6.2 h): the Initialization Vector is excluded from the
     * MAC regardless of the mask supplied. */
    size_t iv_start = frame_header_len + SDLS_SPI_SIZE;
    size_t iv_end = iv_start + (size_t)sa->field_lengths.iv;
    if (iv_end <= total) {
        for (size_t i = iv_start; i < iv_end; i++) {
            out[i] = 0;
        }
    }

    *out_len = total;
    return SDLS_OK;
}

sdls_status_t sdls_sa__cmac_tag(const sdls_security_association_t *sa,
                                 const uint8_t *prefix, size_t prefix_len,
                                 const uint8_t *data, size_t data_len,
                                 uint8_t *mac_out, size_t mac_cap, size_t *mac_len) {
    const sdls_crypto_backend_t *be = sdls_crypto_get_backend();
    if (be == NULL || be->cmac256 == NULL) {
        return SDLS_ERR_NO_CRYPTO_BACKEND;
    }

    size_t total = prefix_len + data_len;
    if (total > SDLS_MAX_AUTH_PAYLOAD_SIZE) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }

    /* The CMAC callback takes one contiguous message, so the masked prefix
     * and the data field are joined here on the stack; bounded by
     * SDLS_MAX_AUTH_PAYLOAD_SIZE, never heap-allocated. */
    uint8_t payload[SDLS_MAX_AUTH_PAYLOAD_SIZE];
    memcpy(payload, prefix, prefix_len);
    memcpy(payload + prefix_len, data, data_len);

    uint8_t tag[16];
    if (be->cmac256(be->user_ctx, sa->key, payload, total, tag) != 0) {
        return SDLS_ERR_CRYPTO_BACKEND_FAILED;
    }

    size_t n = (size_t)sa->field_lengths.mac;
    if (mac_cap < n) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(mac_out, tag, n);
    *mac_len = n;
    return SDLS_OK;
}

sdls_status_t sdls_sa__finish_processing(sdls_security_association_t *sa,
                                          const sdls_security_header_t *header,
                                          size_t *plaintext_len) {
    const uint8_t *counter = header->seq_num;
    size_t counter_len = (size_t)header->fl.seq_num;
    if (sdls_sa__uses_iv_as_sequence(sa)) {
        counter = header->iv;
        counter_len = (size_t)header->fl.iv;
    }

    sdls_status_t st = sdls_sa__check_and_advance_sequence(sa, counter, counter_len);
    if (st != SDLS_OK) {
        return st;
    }

    /* Clause 4.2.3.3 b): fill bytes recorded in the Pad Length field. */
    unsigned pad = sdls_security_header_pad_count(header);
    if (pad > 0) {
        if (pad > *plaintext_len) {
            return SDLS_ERR_INVALID_PAD_LENGTH;
        }
        *plaintext_len -= pad;
    }

    return SDLS_OK;
}
