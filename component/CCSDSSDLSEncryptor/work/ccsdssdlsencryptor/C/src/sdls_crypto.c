/* SPDX-License-Identifier: Apache-2.0 */
#include "sdls_crypto.h"

#include <string.h>

static sdls_crypto_backend_t g_backend;

void sdls_crypto_set_backend(const sdls_crypto_backend_t *backend) {
    if (backend == NULL) {
        memset(&g_backend, 0, sizeof(g_backend));
        return;
    }
    g_backend = *backend;
}

const sdls_crypto_backend_t *sdls_crypto_get_backend(void) {
    return &g_backend;
}
