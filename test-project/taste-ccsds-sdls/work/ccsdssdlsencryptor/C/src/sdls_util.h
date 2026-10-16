/* SPDX-License-Identifier: Apache-2.0
 *
 * Internal big-endian counter arithmetic and constant-time comparison
 * helpers shared by sdls_sa.c, sdls_apply.c and sdls_process.c. Not part of
 * the public API.
 */
#ifndef SDLS_INTERNAL_UTIL_H
#define SDLS_INTERNAL_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include "sdls_errors.h"

/* Adds one to a big-endian integer held in b (n octets), in place. Returns
 * SDLS_ERR_IV_EXHAUSTED rather than wrapping past all-ones -- mirroring
 * incrementBE() in the astro Go reference (pkg/sdls/sa.go). On exhaustion, b
 * is left as all-0xFF so the counter cannot be coaxed into reuse by
 * retrying. */
sdls_status_t sdls_be_increment(uint8_t *b, size_t n);

/* Compares two big-endian unsigned integers of equal width n. Returns <0, 0,
 * >0 as a and b compare. */
int sdls_be_compare(const uint8_t *a, const uint8_t *b, size_t n);

/* Computes diff = a - b for big-endian unsigned integers of width n,
 * assuming a >= b (undefined otherwise). */
void sdls_be_subtract(const uint8_t *a, const uint8_t *b, size_t n, uint8_t *diff);

/* Reports whether a big-endian unsigned integer of width n fits in a
 * uint64_t and, if so, returns its value via *out. Returns 0 (does not fit)
 * when any octet beyond the low 8 sits nonzero. */
int sdls_be_to_u64(const uint8_t *a, size_t n, uint64_t *out);

/* Constant-time comparison: returns 1 if the n-octet buffers are equal, 0
 * otherwise. Runtime does not depend on where they first differ. */
int sdls_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n);

#endif /* SDLS_INTERNAL_UTIL_H */
