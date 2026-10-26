/* SPDX-License-Identifier: Apache-2.0
 *
 * Security Association, ported from the astro Go reference implementation
 * (pkg/sdls/sa.go). A Security Association holds the agreed parameters for
 * one secured Virtual Channel or MAP (clause 4.2.2). Both ends configure a
 * matching SA before the link opens; the SPI travels on the wire so the
 * receiver can find it.
 *
 * A sdls_security_association_t is NOT safe for concurrent use: it carries
 * the sender's IV counter and the receiver's anti-replay state, both of
 * which mutate on every frame. Give each direction of each channel its own
 * SA value.
 *
 * Unlike the Go reference, this struct owns its key and mask storage in
 * fixed-size fields (no heap, no slices) so the whole SA can be a static or
 * stack value.
 */
#ifndef SDLS_SA_H
#define SDLS_SA_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_channel.h"
#include "sdls_errors.h"
#include "sdls_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fixed capacity of the channel binding list, clause 4.2.2.2. */
#ifndef SDLS_MAX_CHANNELS
#define SDLS_MAX_CHANNELS 8
#endif

/* Capacity of the counter buffers used for the anti-replay high-water mark;
 * must be at least max(SDLS_MAX_IV_SIZE, SDLS_MAX_SEQNUM_SIZE). */
#define SDLS_MAX_COUNTER_SIZE SDLS_MAX_IV_SIZE

typedef struct sdls_security_association {
    /* SPI identifies this SA on the wire (clause 4.2.2.3). 0 and 65535 are
     * reserved. */
    uint16_t spi;

    /* The single service type this SA performs (clause 4.2.2.4). */
    sdls_mode_t mode;

    /* The AES-256 key: exactly SDLS_AES_KEY_SIZE octets. Key management
     * (loading, storage, zeroization) is out of scope for this library. */
    uint8_t key[SDLS_AES_KEY_SIZE];

    /* Selects the MAC algorithm when mode is SDLS_MODE_AUTHENTICATION.
     * Ignored for SDLS_MODE_AUTHENTICATED_ENCRYPTION, which is always
     * AES-GCM. */
    sdls_auth_algorithm_t auth_algorithm;

    /* Wire layout of this SA's header and trailer fields. */
    sdls_field_lengths_t field_lengths;

    /* The authentication bit mask of clause 4.2.2.6.2, applied with a
     * bitwise AND to the frame header and security header before the MAC is
     * computed. Caller-owned; must outlive any sdls_apply_security() /
     * sdls_process_security() call and remain at least
     * auth_mask_len octets. NULL (auth_mask_len == 0) means "authenticate
     * every octet of the frame header" -- see the Go reference's caveats on
     * BaselineAuthMask* before relying on that default. The Initialization
     * Vector is excluded from the MAC either way (clause 4.2.2.6.2 h)),
     * enforced regardless of the mask supplied. */
    const uint8_t *auth_mask;
    size_t auth_mask_len;

    /* Channels this SA is bound to, clause 4.2.2.2. An empty list (
     * channels_len == 0) declares no binding: sdls_process_security_for_channel
     * accepts any channel. */
    sdls_channel_id_t channels[SDLS_MAX_CHANNELS];
    size_t channels_len;

    /* The sequence number window of clause 2.3.2.3.3: a positive delta
     * beyond which a received counter is discarded. Zero disables the
     * anti-replay check entirely (testing only). */
    uint64_t seq_window;

    /* --- mutable state; do not set directly --- */

    /* Sender's IV, held as a big-endian integer across the full IV width,
     * incremented once per protected frame. */
    uint8_t iv_counter[SDLS_MAX_IV_SIZE];
    int iv_counter_initialized;

    /* Sender's explicit anti-replay sequence number, clause 4.2.3.4 a). */
    uint8_t seq_counter[SDLS_MAX_SEQNUM_SIZE];
    int seq_counter_initialized;

    /* Highest counter value the receiver has accepted. */
    uint8_t last_seq[SDLS_MAX_COUNTER_SIZE];
    size_t last_seq_len;
    int seq_seen;
} sdls_security_association_t;

/* Checks the SA against the constraints of clause 4.1.1 and clause 4.2.2. */
sdls_status_t sdls_sa_validate(const sdls_security_association_t *sa);

/* Reports whether this SA's configuration actually enforces the anti-replay
 * check of clause 2.3.2.3. */
int sdls_sa_replay_protected(const sdls_security_association_t *sa);

/* Copies the sender's current IV counter into out (out_cap octets
 * available), storing the actual length in *out_len. *out_len is 0 when the
 * SA has no IV field or has not yet protected a frame. Returns
 * SDLS_ERR_BUFFER_TOO_SMALL if out_cap is insufficient. */
sdls_status_t sdls_sa_iv_counter(const sdls_security_association_t *sa,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

/* Restores the sender's IV counter, typically from a checkpoint taken via
 * sdls_sa_iv_counter() before a previous process exited. v_len must equal
 * sa->field_lengths.iv exactly. The next protected frame increments this
 * value before transmitting it, so pass the last value actually sent, not
 * the next one to send. */
sdls_status_t sdls_sa_set_iv_counter(sdls_security_association_t *sa,
                                      const uint8_t *v, size_t v_len);

/* Reports whether ch is in the SA's agreed channel set. An empty set
 * declares no binding, so every channel matches. */
int sdls_sa_serves_channel(const sdls_security_association_t *sa,
                            const sdls_channel_id_t *ch);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_SA_H */
