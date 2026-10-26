#include "sdls_util.h"

sdls_status_t sdls_be_increment(uint8_t *b, size_t n) {
    for (size_t k = n; k > 0; k--) {
        size_t i = k - 1;
        b[i]++;
        if (b[i] != 0) {
            return SDLS_OK;
        }
    }
    /* Every octet wrapped to zero: the counter space is exhausted. Restore
     * the all-ones value so the caller cannot be coaxed into reuse. */
    for (size_t i = 0; i < n; i++) {
        b[i] = 0xFF;
    }
    return SDLS_ERR_IV_EXHAUSTED;
}

int sdls_be_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

void sdls_be_subtract(const uint8_t *a, const uint8_t *b, size_t n, uint8_t *diff) {
    int borrow = 0;
    for (size_t k = n; k > 0; k--) {
        size_t i = k - 1;
        int d = (int)a[i] - (int)b[i] - borrow;
        if (d < 0) {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        diff[i] = (uint8_t)d;
    }
}

int sdls_be_to_u64(const uint8_t *a, size_t n, uint64_t *out) {
    size_t hi = (n > 8) ? (n - 8) : 0;
    for (size_t i = 0; i < hi; i++) {
        if (a[i] != 0) {
            return 0;
        }
    }
    uint64_t v = 0;
    for (size_t i = hi; i < n; i++) {
        v = (v << 8) | a[i];
    }
    *out = v;
    return 1;
}

int sdls_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}
