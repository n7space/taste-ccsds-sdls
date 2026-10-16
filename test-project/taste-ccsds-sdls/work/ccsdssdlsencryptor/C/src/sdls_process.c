/* SPDX-License-Identifier: Apache-2.0
 *
 * Ported from the astro Go reference implementation (pkg/sdls/process.go).
 */
#include "sdls_process.h"

#include <string.h>

#include "sdls_header.h"
#include "sdls_gcm.h"
#include "sdls_sa_internal.h"
#include "sdls_util.h"

sdls_status_t sdls_static_lookup_init(sdls_static_lookup_t *lookup,
                                      sdls_security_association_t **sas, size_t count) {
    if (lookup == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (count > SDLS_MAX_LOOKUP_ENTRIES) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }
    lookup->count = 0;
    for (size_t i = 0; i < count; i++) {
        if (sas[i] != NULL) {
            lookup->sas[lookup->count++] = sas[i];
        }
    }
    return SDLS_OK;
}

sdls_status_t sdls_static_lookup_fn(void *user_ctx, uint16_t spi,
                                    sdls_security_association_t **sa_out) {
    const sdls_static_lookup_t *lookup = (const sdls_static_lookup_t *)user_ctx;
    if (lookup == NULL) {
        return SDLS_ERR_UNKNOWN_SPI;
    }
    for (size_t i = 0; i < lookup->count; i++) {
        if (lookup->sas[i]->spi == spi) {
            *sa_out = lookup->sas[i];
            return SDLS_OK;
        }
    }
    return SDLS_ERR_UNKNOWN_SPI;
}

/* Shared body of sdls_process_security and sdls_process_security_for_channel;
 * ch is NULL when the caller supplied no channel context. */
static sdls_status_t process_security(const uint8_t *data_field, size_t data_field_len,
                                       const uint8_t *frame_header, size_t frame_header_len,
                                       const sdls_channel_id_t *ch,
                                       sdls_sa_lookup_fn lookup, void *lookup_ctx,
                                       sdls_security_header_t *header_out,
                                       uint8_t *plaintext_out, size_t plaintext_cap,
                                       size_t *plaintext_len) {
    if (lookup == NULL) {
        return SDLS_ERR_UNKNOWN_SPI;
    }
    if (frame_header_len > SDLS_MAX_FRAME_HEADER_SIZE) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (frame_header_len > 0 && frame_header == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    /* The SPI is always the leading two octets, whatever the SA says (clause
     * 4.1.1.2.1). */
    if (data_field_len < SDLS_SPI_SIZE) {
        return SDLS_ERR_DATA_TOO_SHORT;
    }

    uint16_t spi = (uint16_t)(((uint16_t)data_field[0] << 8) | data_field[1]);

    sdls_security_association_t *sa = NULL;
    sdls_status_t st = lookup(lookup_ctx, spi, &sa);
    if (st != SDLS_OK) {
        return st;
    }
    if (sa == NULL) {
        return SDLS_ERR_UNKNOWN_SPI;
    }
    st = sdls_sa_validate(sa);
    if (st != SDLS_OK) {
        return st;
    }
    /* Clause 4.2.4.3: the SA must be the one agreed for the channel the
     * frame arrived on. Checked before any cryptographic work, like the
     * SPI. */
    if (ch != NULL && !sdls_sa_serves_channel(sa, ch)) {
        return SDLS_ERR_SA_CHANNEL_MISMATCH;
    }

    sdls_security_header_t header;
    size_t consumed;
    st = sdls_header_decode(data_field, data_field_len, &sa->field_lengths, &header, &consumed);
    if (st != SDLS_OK) {
        return st;
    }

    size_t mac_len = (size_t)sa->field_lengths.mac;
    if (data_field_len < consumed + mac_len) {
        return SDLS_ERR_DATA_TOO_SHORT;
    }

    const uint8_t *header_bytes = data_field;
    size_t header_bytes_len = consumed;
    const uint8_t *body = data_field + consumed;
    size_t body_len = data_field_len - consumed - mac_len;
    const uint8_t *mac = data_field + data_field_len - mac_len;

    if (body_len > SDLS_MAX_DATA_SIZE) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_out != NULL && plaintext_cap < body_len) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t prefix[SDLS_MAX_FRAME_HEADER_SIZE + SDLS_MAX_SECURITY_HEADER_SIZE];
    size_t prefix_len;
    st = sdls_sa__build_auth_payload_prefix(sa, frame_header, frame_header_len,
                                            header_bytes, header_bytes_len,
                                            prefix, sizeof(prefix), &prefix_len);
    if (st != SDLS_OK) {
        return st;
    }

    size_t pt_len = body_len;

    /* CMAC is not an AEAD: verify the tag directly and take the body as it
     * stands, since clause E2 authenticates without encrypting. */
    if (sdls_sa__uses_cmac(sa)) {
        uint8_t expected[SDLS_MAX_MAC_SIZE];
        size_t expected_len;
        st = sdls_sa__cmac_tag(sa, prefix, prefix_len, body, body_len, expected, sizeof(expected), &expected_len);
        if (st != SDLS_OK) {
            return st;
        }
        /* Constant time: a variable-time compare would leak how many
         * leading octets of a forged tag were correct. */
        if (!sdls_constant_time_equal(expected, mac, mac_len)) {
            return SDLS_ERR_AUTHENTICATION_FAILED;
        }
        memmove(plaintext_out, body, body_len);
    } else {
        if ((size_t)header.fl.iv != SDLS_GCM_IV_SIZE) {
            return SDLS_ERR_INVALID_FIELD_LENGTHS;
        }

        switch (sa->mode) {
            case SDLS_MODE_ENCRYPTION:
                /* Nothing to verify: mac_len is 0, the body is all
                 * ciphertext. */
                st = sdls_gcm_ctr_crypt(sa->key, header.iv, body, body_len, plaintext_out);
                if (st != SDLS_OK) {
                    return st;
                }
                break;

            case SDLS_MODE_AUTHENTICATED_ENCRYPTION:
                st = sdls_gcm_open(sa->key, header.iv, body, body_len, mac, mac_len,
                                   prefix, prefix_len, plaintext_out);
                if (st != SDLS_OK) {
                    return st;
                }
                break;

            case SDLS_MODE_AUTHENTICATION: {
                uint8_t aad[SDLS_MAX_AUTH_PAYLOAD_SIZE];
                size_t aad_len = prefix_len + body_len;
                if (aad_len > sizeof(aad)) {
                    return SDLS_ERR_BUFFER_TOO_SMALL;
                }
                memcpy(aad, prefix, prefix_len);
                if (body_len > 0) {
                    memcpy(aad + prefix_len, body, body_len);
                }
                st = sdls_gcm_open(sa->key, header.iv, NULL, 0, mac, mac_len, aad, aad_len, NULL);
                if (st != SDLS_OK) {
                    return st;
                }
                memmove(plaintext_out, body, body_len);
                break;
            }

            default:
                return SDLS_ERR_UNSUPPORTED_MODE;
        }
    }

    /* Anti-replay runs only now, after the MAC has verified, so a forged
     * frame cannot advance the receiver's window (clause 4.2.4.4). */
    st = sdls_sa__finish_processing(sa, &header, &pt_len);
    if (st != SDLS_OK) {
        return st;
    }

    if (header_out != NULL) {
        *header_out = header;
    }
    *plaintext_len = pt_len;
    return SDLS_OK;
}

sdls_status_t sdls_process_security(const uint8_t *data_field, size_t data_field_len,
                                     const uint8_t *frame_header, size_t frame_header_len,
                                     sdls_sa_lookup_fn lookup, void *lookup_ctx,
                                     sdls_security_header_t *header_out,
                                     uint8_t *plaintext_out, size_t plaintext_cap,
                                     size_t *plaintext_len) {
    return process_security(data_field, data_field_len, frame_header, frame_header_len, NULL,
                             lookup, lookup_ctx, header_out, plaintext_out, plaintext_cap, plaintext_len);
}

sdls_status_t sdls_process_security_for_channel(const uint8_t *data_field, size_t data_field_len,
                                                 const uint8_t *frame_header, size_t frame_header_len,
                                                 const sdls_channel_id_t *ch,
                                                 sdls_sa_lookup_fn lookup, void *lookup_ctx,
                                                 sdls_security_header_t *header_out,
                                                 uint8_t *plaintext_out, size_t plaintext_cap,
                                                 size_t *plaintext_len) {
    return process_security(data_field, data_field_len, frame_header, frame_header_len, ch,
                             lookup, lookup_ctx, header_out, plaintext_out, plaintext_cap, plaintext_len);
}
