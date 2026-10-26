/* SPDX-License-Identifier: Apache-2.0 */
#include "sdls_channel.h"

int sdls_channel_id_equal(const sdls_channel_id_t *a, const sdls_channel_id_t *b) {
    return a->tfvn == b->tfvn && a->scid == b->scid && a->vcid == b->vcid && a->map_id == b->map_id;
}
