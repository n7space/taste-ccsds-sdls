/* SPDX-License-Identifier: Apache-2.0
 *
 * Ported from the astro Go reference implementation (pkg/sdls/apply.go).
 */
#include "sdls_apply.h"

#include <string.h>

#include "sdls_header.h"
#include "sdls_gcm.h"
#include "sdls_sa_internal.h"

sdls_status_t sdls_apply_security(sdls_security_association_t *sa,
                                   const uint8_t *frame_header, size_t frame_header_len,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *out, size_t out_cap, size_t *out_len) {
    if (sa == NULL || out == NULL || out_len == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (frame_header_len > SDLS_MAX_FRAME_HEADER_SIZE || plaintext_len > SDLS_MAX_DATA_SIZE) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (frame_header_len > 0 && frame_header == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len > 0 && plaintext == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }

    sdls_status_t st = sdls_sa_validate(sa);
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t iv[SDLS_MAX_IV_SIZE];
    size_t iv_len;
    st = sdls_sa__next_iv(sa, iv, &iv_len);
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t seq[SDLS_MAX_SEQNUM_SIZE];
    size_t seq_len;
    st = sdls_sa__next_seq(sa, seq, &seq_len);
    if (st != SDLS_OK) {
        return st;
    }

    sdls_security_header_t header;
    memset(&header, 0, sizeof(header));
    header.spi = sa->spi;
    header.fl = sa->field_lengths;
    if (iv_len > 0) {
        memcpy(header.iv, iv, iv_len);
    }
    if (seq_len > 0) {
        memcpy(header.seq_num, seq, seq_len);
    }
    /* header.pad_length is already zero-filled: the Pad Length field, when
     * present, is transmitted as zeros (clause E1.2 note 2; this library
     * performs no block padding). */

    uint8_t header_bytes[SDLS_MAX_SECURITY_HEADER_SIZE];
    size_t header_bytes_len;
    st = sdls_header_encode(&header, header_bytes, sizeof(header_bytes), &header_bytes_len);
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t prefix[SDLS_MAX_FRAME_HEADER_SIZE + SDLS_MAX_SECURITY_HEADER_SIZE];
    size_t prefix_len;
    st = sdls_sa__build_auth_payload_prefix(sa, frame_header, frame_header_len,
                                            header_bytes, header_bytes_len,
                                            prefix, sizeof(prefix), &prefix_len);
    if (st != SDLS_OK) {
        return st;
    }

    size_t mac_len = (size_t)sa->field_lengths.mac;
    size_t needed = header_bytes_len + plaintext_len + mac_len;
    if (out_cap < needed) {
        return SDLS_ERR_BUFFER_TOO_SMALL;
    }

    /* CMAC is not an AEAD and needs no nonce, so it does not go through the
     * GCM construction at all. */
    if (sdls_sa__uses_cmac(sa)) {
        uint8_t mac[SDLS_MAX_MAC_SIZE];
        size_t mac_written;
        st = sdls_sa__cmac_tag(sa, prefix, prefix_len, plaintext, plaintext_len, mac, sizeof(mac), &mac_written);
        if (st != SDLS_OK) {
            return st;
        }

        size_t off = 0;
        memcpy(out + off, header_bytes, header_bytes_len);
        off += header_bytes_len;
        if (plaintext_len > 0) {
            memcpy(out + off, plaintext, plaintext_len);
        }
        off += plaintext_len;
        memcpy(out + off, mac, mac_written);
        off += mac_written;

        *out_len = off;
        return SDLS_OK;
    }

    size_t off = 0;
    memcpy(out, header_bytes, header_bytes_len);
    off += header_bytes_len;

    switch (sa->mode) {
        case SDLS_MODE_ENCRYPTION: {
            /* Clause 4.2.3.2.2.1: the data field is encrypted and no
             * Security Trailer is produced. Not in the astro reference;
             * clause 2.3.3 warns that encryption without authentication
             * offers no integrity -- prefer authenticated encryption. */
            st = sdls_gcm_ctr_crypt(sa->key, iv, plaintext, plaintext_len, out + off);
            if (st != SDLS_OK) {
                return st;
            }
            off += plaintext_len;
            break;
        }

        case SDLS_MODE_AUTHENTICATED_ENCRYPTION: {
            /* Clause 4.2.3.2.2.3: plaintext is the data field, associated
             * data is the masked prefix. */
            uint8_t tag[SDLS_MAX_MAC_SIZE];
            st = sdls_gcm_seal(sa->key, iv, plaintext, plaintext_len,
                               prefix, prefix_len, mac_len,
                               out + off, tag);
            if (st != SDLS_OK) {
                return st;
            }
            off += plaintext_len;
            memcpy(out + off, tag, mac_len);
            off += mac_len;
            break;
        }

        case SDLS_MODE_AUTHENTICATION: {
            /* Clause 4.2.3.2.2.2: the data field travels unencrypted and the
             * MAC covers the whole Authentication Payload. Sealing an empty
             * plaintext with prefix||plaintext as associated data is GMAC
             * over exactly that. */
            uint8_t aad[SDLS_MAX_AUTH_PAYLOAD_SIZE];
            size_t aad_len = prefix_len + plaintext_len;
            if (aad_len > sizeof(aad)) {
                return SDLS_ERR_BUFFER_TOO_SMALL;
            }
            memcpy(aad, prefix, prefix_len);
            if (plaintext_len > 0) {
                memcpy(aad + prefix_len, plaintext, plaintext_len);
            }

            uint8_t tag[SDLS_MAX_MAC_SIZE];
            st = sdls_gcm_seal(sa->key, iv, NULL, 0, aad, aad_len, mac_len, NULL, tag);
            if (st != SDLS_OK) {
                return st;
            }

            if (plaintext_len > 0) {
                memcpy(out + off, plaintext, plaintext_len);
            }
            off += plaintext_len;
            memcpy(out + off, tag, mac_len);
            off += mac_len;
            break;
        }

        default:
            return SDLS_ERR_UNSUPPORTED_MODE;
    }

    *out_len = off;
    return SDLS_OK;
}
