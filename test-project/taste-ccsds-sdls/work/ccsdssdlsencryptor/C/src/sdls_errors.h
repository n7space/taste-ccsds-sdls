/* SPDX-License-Identifier: Apache-2.0
 *
 * Status/error codes for the SDLS library, mirroring the sentinel errors of
 * the astro Go reference implementation (pkg/sdls/errors.go).
 */
#ifndef SDLS_ERRORS_H
#define SDLS_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sdls_status {
    SDLS_OK = 0,

    /* Input is shorter than the fields it must contain. */
    SDLS_ERR_DATA_TOO_SHORT,
    /* Reserved SPI value (0 or 65535), CCSDS 355.0-B-2 4.1.1.2.3. */
    SDLS_ERR_INVALID_SPI,
    /* SA key is not a valid AES-256 key (32 octets). */
    SDLS_ERR_INVALID_KEY,
    /* SA service type is zero or unknown. */
    SDLS_ERR_INVALID_MODE,
    /* SA's managed field widths are unusable. */
    SDLS_ERR_INVALID_FIELD_LENGTHS,
    /* Security header exceeds the 64-octet cap, clause 4.1.1.1.4. */
    SDLS_ERR_HEADER_TOO_LONG,
    /* Service type not implemented. */
    SDLS_ERR_UNSUPPORTED_MODE,
    /* No Security Association registered for the SPI. */
    SDLS_ERR_UNKNOWN_SPI,
    /* MAC did not verify. */
    SDLS_ERR_AUTHENTICATION_FAILED,
    /* Anti-replay check rejected the frame, clause 2.3.2.3. */
    SDLS_ERR_REPLAY_DETECTED,
    /* Initialization vector counter space exhausted for this key. */
    SDLS_ERR_IV_EXHAUSTED,
    /* SA named by the SPI is not bound to the channel, clause 4.2.4.3. */
    SDLS_ERR_SA_CHANNEL_MISMATCH,
    /* Authentication bit mask shorter than the data it must cover. */
    SDLS_ERR_MASK_TOO_SHORT,
    /* Pad Length field describes more fill bytes than the data contains. */
    SDLS_ERR_INVALID_PAD_LENGTH,
    /* IV counter restore value does not match the SA's configured IV width. */
    SDLS_ERR_INVALID_IV_COUNTER,
    /* SA requests anti-replay but carries no IV or sequence number field. */
    SDLS_ERR_NO_ANTI_REPLAY_COUNTER,

    /* Errors specific to this C implementation's fixed-size buffers and
     * mandatory crypto backend registration (no equivalent in astro). */
    SDLS_ERR_BUFFER_TOO_SMALL,
    SDLS_ERR_NO_CRYPTO_BACKEND,
    SDLS_ERR_CRYPTO_BACKEND_FAILED,
    SDLS_ERR_INVALID_ARGUMENT,
} sdls_status_t;

/* Returns a short human-readable string naming the status code. */
const char *sdls_status_string(sdls_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_ERRORS_H */
