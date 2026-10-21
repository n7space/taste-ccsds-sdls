/* SPDX-License-Identifier: Apache-2.0
 *
 * Channel binding for Security Associations, ported from the astro Go
 * reference implementation (pkg/sdls/channel.go).
 */
#ifndef SDLS_CHANNEL_H
#define SDLS_CHANNEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Marks a sdls_channel_id_t.map_id whose frame type has no MAP multiplexing,
 * or a USLP/TC channel where the MAP ID is not part of the binding. */
#define SDLS_NO_MAP (-1)

/* Names one channel a Security Association can be bound to: a Global
 * Virtual Channel Identifier (Transfer Frame Version Number, Spacecraft ID,
 * Virtual Channel ID), optionally extended to a Global MAP ID with the MAP
 * ID of a TC or USLP frame.
 *
 * Clause 4.2.2.2 requires a Security Association to apply to an agreed set
 * of GVCIDs or GMAP_IDs, and clause 4.2.4.3 requires the receiving end to
 * verify that the SA named by the SPI is in fact the one for the channel the
 * frame arrived on. List the agreed channels in
 * sdls_security_association_t.channels and call
 * sdls_process_security_for_channel() to have that check enforced. */
typedef struct sdls_channel_id {
    /* Transfer Frame Version Number: 0 for TM, 1 for TC and AOS (each per
     * its own numbering), 12 (0b1100) for USLP. */
    uint8_t tfvn;
    /* Spacecraft Identifier. */
    uint16_t scid;
    /* Virtual Channel Identifier. */
    uint8_t vcid;
    /* Extends the GVCID to a GMAP_ID for TC and USLP. Set to SDLS_NO_MAP
     * when the frames have no MAP, or when the binding stops at the virtual
     * channel. */
    int map_id;
} sdls_channel_id_t;

/* Reports whether a and b name the same channel. */
int sdls_channel_id_equal(const sdls_channel_id_t *a, const sdls_channel_id_t *b);

#ifdef __cplusplus
}
#endif

#endif /* SDLS_CHANNEL_H */
