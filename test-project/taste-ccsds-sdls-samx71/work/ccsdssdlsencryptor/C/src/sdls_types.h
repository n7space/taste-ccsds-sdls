/* SPDX-License-Identifier: Apache-2.0
 *
 * Core constants and value types for the SDLS library, per CCSDS 355.0-B-2.
 * Ported from the astro Go reference implementation (pkg/sdls/header.go,
 * pkg/sdls/sa.go). This implementation performs no dynamic allocation: every
 * variable-width field is backed by a fixed-size buffer sized to the widest
 * value this library supports; the SDLS_MAX_* constants below document those
 * caps and may be overridden at build time if a mission needs more.
 */
#ifndef SDLS_TYPES_H
#define SDLS_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Largest permitted Security Header, CCSDS 355.0-B-2 clause 4.1.1.1.4. */
#define SDLS_MAX_SECURITY_HEADER_SIZE 64

/* Width of the Security Parameter Index field, in octets (clause 4.1.1.2.1). */
#define SDLS_SPI_SIZE 2

/* Reserved Security Parameter Index values, clause 4.1.1.2.3. */
#define SDLS_SPI_RESERVED_ZERO     0
#define SDLS_SPI_RESERVED_ALL_ONES 65535

/* AES-256 key width in octets, clause E1.1 a). */
#define SDLS_AES_KEY_SIZE 32

/* GCM initialization vector width in octets (96 bits, clause E1.1 b). */
#define SDLS_GCM_IV_SIZE 12

/* MAC width bounds this library accepts, in octets. GCM/GMAC need at least
 * 12; CMAC (SP 800-38B clause 6.4) permits any truncation down to 1. */
#define SDLS_MIN_MAC_SIZE  12
#define SDLS_MIN_CMAC_SIZE 1
#define SDLS_MAX_MAC_SIZE  16

/* Capacity, in octets, of the fixed buffers backing the optional Security
 * Header fields. The Security Header as a whole is capped at
 * SDLS_MAX_SECURITY_HEADER_SIZE regardless; these are per-field ceilings
 * comfortably above any CCSDS-defined baseline (clause E1/E2/E3/E4). */
#ifndef SDLS_MAX_IV_SIZE
#define SDLS_MAX_IV_SIZE 16
#endif
#ifndef SDLS_MAX_SEQNUM_SIZE
#define SDLS_MAX_SEQNUM_SIZE 8
#endif
#ifndef SDLS_MAX_PADLEN_SIZE
#define SDLS_MAX_PADLEN_SIZE 4
#endif

/* Caps for the frame header / data field this library will process in one
 * call. No equivalent exists in the astro Go package, which relies on the
 * garbage collector; this C port must fix a ceiling so it never allocates.
 * Override at build time (e.g. -DSDLS_MAX_FRAME_HEADER_SIZE=512) for
 * missions with larger frames. */
#ifndef SDLS_MAX_FRAME_HEADER_SIZE
#define SDLS_MAX_FRAME_HEADER_SIZE 256
#endif
#ifndef SDLS_MAX_DATA_SIZE
#define SDLS_MAX_DATA_SIZE 2048
#endif

/* Largest protected frame (Security Header + data + Security Trailer) this
 * library will produce or consume in one call. */
#define SDLS_MAX_PROTECTED_SIZE \
    (SDLS_MAX_SECURITY_HEADER_SIZE + SDLS_MAX_DATA_SIZE + SDLS_MAX_MAC_SIZE)

/* Largest Authentication Payload (masked frame header + security header,
 * then the data field) this library assembles on the stack while computing
 * a CMAC or GMAC tag. */
#define SDLS_MAX_AUTH_PAYLOAD_SIZE \
    (SDLS_MAX_FRAME_HEADER_SIZE + SDLS_MAX_SECURITY_HEADER_SIZE + SDLS_MAX_DATA_SIZE)

/* Security Association service type, clause 4.2.2.4. Every SA performs one and
 * only one of these. */
typedef enum sdls_mode {
    SDLS_MODE_UNSPECIFIED = 0,

    /* Proves integrity and origin without hiding the data. Algorithm chosen
     * by sdls_auth_algorithm_t: AES-CMAC for the clause E2 telecommand
     * baseline, or GMAC as the authentication-only companion to the
     * AES-GCM baselines of clause E1/E3/E4. */
    SDLS_MODE_AUTHENTICATION = 1,

    /* Hides the data without authenticating it. Clause 2.3.3 warns this can
     * give a false sense of security. The astro reference does not
     * implement it; this port does, as the AES-256-GCM keystream without a
     * tag (i.e. AES-256-CTR): 96-bit IV, no MAC, no Security Trailer. */
    SDLS_MODE_ENCRYPTION = 2,

    /* The clause E1/E3/E4 baseline: AES-256-GCM with a 96-bit IV and a
     * 128-bit MAC. */
    SDLS_MODE_AUTHENTICATED_ENCRYPTION = 3
} sdls_mode_t;

/* Selects the MAC algorithm used when mode is SDLS_MODE_AUTHENTICATION. */
typedef enum sdls_auth_algorithm {
    /* AES-GCM over an empty plaintext with the whole Authentication Payload
     * as associated data. Not itself an annex baseline, but the natural
     * authentication-only companion to clause E1/E3/E4. Zero value. */
    SDLS_AUTH_GMAC = 0,

    /* AES-CMAC, the clause E2 telecommand baseline: 256-bit key, 128-bit MAC
     * (truncatable). Clause E2.2 fixes the IV field at zero octets wide. */
    SDLS_AUTH_CMAC = 1
} sdls_auth_algorithm_t;

/* Octet widths of the managed Security Header and Security Trailer fields
 * for one Security Association. Every width is fixed for the SA's lifetime
 * (clause 2.3.1.4, clause 4.2.2.5). A width of zero means the field is absent. */
typedef struct sdls_field_lengths {
    int iv;      /* Initialization Vector, clause 4.1.1.3 */
    int seq_num; /* anti-replay Sequence Number, clause 4.1.1.4 */
    int pad_len; /* Pad Length, clause 4.1.1.5 */
    int mac;     /* Message Authentication Code in the trailer, clause 4.1.2.3 */
} sdls_field_lengths_t;

/* Encoded width of a Security Header with these field lengths, including the
 * mandatory 2-octet SPI. */
size_t sdls_field_lengths_header_size(const sdls_field_lengths_t *fl);

/* Reports whether the field widths are usable and fit within
 * SDLS_MAX_SECURITY_HEADER_SIZE and this library's fixed field buffers. */
sdls_status_t sdls_field_lengths_validate(const sdls_field_lengths_t *fl);

/* The Security Header of clause 4.1.1: a mandatory SPI followed by three
 * optional fields, contiguous and in this order. Field bytes are stored in
 * fixed-capacity arrays; only the first {iv,seq_num,pad_len} octets of each
 * are meaningful, per the field lengths supplied when decoding. */
typedef struct sdls_security_header {
    uint16_t spi;
    uint8_t  iv[SDLS_MAX_IV_SIZE];
    uint8_t  seq_num[SDLS_MAX_SEQNUM_SIZE];
    uint8_t  pad_length[SDLS_MAX_PADLEN_SIZE];
    sdls_field_lengths_t fl; /* widths actually populated above */
} sdls_security_header_t;

/* Returns the Pad Length field as an integer. An absent field means no
 * padding. */
unsigned sdls_security_header_pad_count(const sdls_security_header_t *h);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_TYPES_H */
