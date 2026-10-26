/* SPDX-License-Identifier: Apache-2.0 */
#include "sdls_gcm.h"

#include <string.h>

#include "sdls_crypto.h"
#include "sdls_util.h"

#define GCM_BLOCK_SIZE 16

static sdls_status_t aes_block(const uint8_t key[SDLS_AES_KEY_SIZE],
                                const uint8_t in[16], uint8_t out[16]) {
    const sdls_crypto_backend_t *be = sdls_crypto_get_backend();
    if (be == NULL || be->aes256_encrypt_block == NULL) {
        return SDLS_ERR_NO_CRYPTO_BACKEND;
    }
    if (be->aes256_encrypt_block(be->user_ctx, key, in, out) != 0) {
        return SDLS_ERR_CRYPTO_BACKEND_FAILED;
    }
    return SDLS_OK;
}

/* GF(2^128) multiplication, NIST SP 800-38D clause 6.3 algorithm 1. x and y
 * are 16-octet blocks in the spec's bit-endian convention (bit 0 is the MSB
 * of the first octet). Writes x*y to out (may alias x or y). */
static void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);

    for (int i = 0; i < 128; i++) {
        int byte_i = i / 8;
        int bit_i = 7 - (i % 8);
        if ((x[byte_i] >> bit_i) & 1) {
            for (int j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] = (uint8_t)(v[0] >> 1);
        if (lsb) {
            v[0] ^= 0xe1; /* R = 11100001 || 0^120 */
        }
    }
    memcpy(out, z, 16);
}

/* GHASH over aad then c, per NIST SP 800-38D clause 6.4. */
static void ghash(const uint8_t h[16], const uint8_t *aad, size_t aad_len,
                   const uint8_t *c, size_t c_len, uint8_t out[16]) {
    uint8_t y[16] = {0};
    uint8_t block[16];
    size_t i;

    for (i = 0; i + GCM_BLOCK_SIZE <= aad_len; i += GCM_BLOCK_SIZE) {
        for (int j = 0; j < 16; j++) {
            y[j] ^= aad[i + j];
        }
        gf128_mul(y, h, y);
    }
    if (i < aad_len) {
        memset(block, 0, sizeof(block));
        memcpy(block, aad + i, aad_len - i);
        for (int j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        gf128_mul(y, h, y);
    }

    for (i = 0; i + GCM_BLOCK_SIZE <= c_len; i += GCM_BLOCK_SIZE) {
        for (int j = 0; j < 16; j++) {
            y[j] ^= c[i + j];
        }
        gf128_mul(y, h, y);
    }
    if (i < c_len) {
        memset(block, 0, sizeof(block));
        memcpy(block, c + i, c_len - i);
        for (int j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        gf128_mul(y, h, y);
    }

    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t c_bits = (uint64_t)c_len * 8;
    uint8_t len_block[16];
    for (int j = 0; j < 8; j++) {
        len_block[j] = (uint8_t)(aad_bits >> (56 - 8 * j));
        len_block[8 + j] = (uint8_t)(c_bits >> (56 - 8 * j));
    }
    for (int j = 0; j < 16; j++) {
        y[j] ^= len_block[j];
    }
    gf128_mul(y, h, y);

    memcpy(out, y, 16);
}

/* Increments the low-order 32 bits of a 128-bit block, mod 2^32, leaving the
 * high-order 96 bits unchanged (NIST SP 800-38D clause 6.2, inc32). */
static void inc32(uint8_t block[16]) {
    uint32_t ctr = ((uint32_t)block[12] << 24) | ((uint32_t)block[13] << 16) |
                   ((uint32_t)block[14] << 8) | (uint32_t)block[15];
    ctr++;
    block[12] = (uint8_t)(ctr >> 24);
    block[13] = (uint8_t)(ctr >> 16);
    block[14] = (uint8_t)(ctr >> 8);
    block[15] = (uint8_t)ctr;
}

/* GCTR: XORs in with the AES-CTR keystream starting at inc32(icb), per NIST
 * SP 800-38D clause 6.5. in and out may alias. */
static sdls_status_t gctr(const uint8_t key[SDLS_AES_KEY_SIZE], const uint8_t icb[16],
                           const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t ctr[16];
    uint8_t ks[16];
    memcpy(ctr, icb, 16);

    size_t i;
    for (i = 0; i + GCM_BLOCK_SIZE <= len; i += GCM_BLOCK_SIZE) {
        inc32(ctr);
        sdls_status_t st = aes_block(key, ctr, ks);
        if (st != SDLS_OK) {
            return st;
        }
        for (int j = 0; j < 16; j++) {
            out[i + j] = (uint8_t)(in[i + j] ^ ks[j]);
        }
    }
    if (i < len) {
        inc32(ctr);
        sdls_status_t st = aes_block(key, ctr, ks);
        if (st != SDLS_OK) {
            return st;
        }
        size_t rem = len - i;
        for (size_t j = 0; j < rem; j++) {
            out[i + j] = (uint8_t)(in[i + j] ^ ks[j]);
        }
    }
    return SDLS_OK;
}

/* Builds J0 = IV || 0^31 || 1, the NIST SP 800-38D clause 7.1 special case
 * for a 96-bit IV, which is the only width CCSDS 355.0-B-2 uses. */
static void build_j0(const uint8_t iv[SDLS_GCM_IV_SIZE], uint8_t j0[16]) {
    memcpy(j0, iv, SDLS_GCM_IV_SIZE);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
}

sdls_status_t sdls_gcm_seal(const uint8_t key[SDLS_AES_KEY_SIZE],
                            const uint8_t iv[SDLS_GCM_IV_SIZE],
                            const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *aad, size_t aad_len,
                            size_t tag_size,
                            uint8_t *out_ciphertext, uint8_t *out_tag) {
    if (tag_size < SDLS_MIN_MAC_SIZE || tag_size > SDLS_MAX_MAC_SIZE || out_tag == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len > 0 && (plaintext == NULL || out_ciphertext == NULL)) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }

    uint8_t h[16] = {0};
    sdls_status_t st = aes_block(key, h, h); /* H = AES-256(key, 0^128) */
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t j0[16];
    build_j0(iv, j0);

    if (plaintext_len > 0) {
        st = gctr(key, j0, plaintext, plaintext_len, out_ciphertext);
        if (st != SDLS_OK) {
            return st;
        }
    }

    uint8_t s[16];
    ghash(h, aad, aad_len, plaintext_len > 0 ? out_ciphertext : NULL, plaintext_len, s);

    uint8_t ej0[16];
    st = aes_block(key, j0, ej0);
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t tag[16];
    for (int j = 0; j < 16; j++) {
        tag[j] = (uint8_t)(s[j] ^ ej0[j]);
    }
    memcpy(out_tag, tag, tag_size);
    return SDLS_OK;
}

sdls_status_t sdls_gcm_open(const uint8_t key[SDLS_AES_KEY_SIZE],
                            const uint8_t iv[SDLS_GCM_IV_SIZE],
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *tag, size_t tag_size,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *out_plaintext) {
    if (tag_size < SDLS_MIN_MAC_SIZE || tag_size > SDLS_MAX_MAC_SIZE || tag == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    if (ciphertext_len > 0 && (ciphertext == NULL || out_plaintext == NULL)) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }

    uint8_t h[16] = {0};
    sdls_status_t st = aes_block(key, h, h);
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t j0[16];
    build_j0(iv, j0);

    uint8_t s[16];
    ghash(h, aad, aad_len, ciphertext, ciphertext_len, s);

    uint8_t ej0[16];
    st = aes_block(key, j0, ej0);
    if (st != SDLS_OK) {
        return st;
    }

    uint8_t expected[16];
    for (int j = 0; j < 16; j++) {
        expected[j] = (uint8_t)(s[j] ^ ej0[j]);
    }

    /* Constant time: a variable-time compare would leak how many leading
     * octets of a forged tag were correct. */
    if (!sdls_constant_time_equal(expected, tag, tag_size)) {
        return SDLS_ERR_AUTHENTICATION_FAILED;
    }

    if (ciphertext_len > 0) {
        st = gctr(key, j0, ciphertext, ciphertext_len, out_plaintext);
        if (st != SDLS_OK) {
            return st;
        }
    }
    return SDLS_OK;
}

sdls_status_t sdls_gcm_ctr_crypt(const uint8_t key[SDLS_AES_KEY_SIZE],
                                 const uint8_t iv[SDLS_GCM_IV_SIZE],
                                 const uint8_t *in, size_t len, uint8_t *out) {
    if (len == 0) {
        return SDLS_OK;
    }
    if (in == NULL || out == NULL) {
        return SDLS_ERR_INVALID_ARGUMENT;
    }
    uint8_t j0[16];
    build_j0(iv, j0);
    return gctr(key, j0, in, len, out);
}
