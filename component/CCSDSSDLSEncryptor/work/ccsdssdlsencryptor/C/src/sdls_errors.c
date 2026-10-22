/* SPDX-License-Identifier: Apache-2.0 */
#include "sdls_errors.h"

const char *sdls_status_string(sdls_status_t status) {
    switch (status) {
        case SDLS_OK: return "ok";
        case SDLS_ERR_DATA_TOO_SHORT: return "data too short for the security header or trailer";
        case SDLS_ERR_INVALID_SPI: return "invalid SPI: 0 and 65535 are reserved by CCSDS";
        case SDLS_ERR_INVALID_KEY: return "invalid key: AES-256 requires exactly 32 bytes";
        case SDLS_ERR_INVALID_MODE: return "invalid mode: must be authentication, encryption, or authenticated encryption";
        case SDLS_ERR_INVALID_FIELD_LENGTHS: return "invalid field lengths for the security header or trailer";
        case SDLS_ERR_HEADER_TOO_LONG: return "security header exceeds the maximum of 64 octets";
        case SDLS_ERR_UNSUPPORTED_MODE: return "unsupported mode";
        case SDLS_ERR_UNKNOWN_SPI: return "unknown SPI: no security association registered";
        case SDLS_ERR_AUTHENTICATION_FAILED: return "authentication failed";
        case SDLS_ERR_REPLAY_DETECTED: return "replay detected: sequence number rejected";
        case SDLS_ERR_IV_EXHAUSTED: return "initialization vector space exhausted for this key";
        case SDLS_ERR_SA_CHANNEL_MISMATCH: return "security association is not bound to this channel";
        case SDLS_ERR_MASK_TOO_SHORT: return "authentication bit mask is shorter than the data it must cover";
        case SDLS_ERR_INVALID_PAD_LENGTH: return "pad length exceeds the recovered data field";
        case SDLS_ERR_INVALID_IV_COUNTER: return "invalid IV counter: length does not match field_lengths.iv";
        case SDLS_ERR_NO_ANTI_REPLAY_COUNTER: return "anti-replay requested but the SA carries no IV or sequence number field to check";
        case SDLS_ERR_BUFFER_TOO_SMALL: return "caller-supplied buffer is too small";
        case SDLS_ERR_NO_CRYPTO_BACKEND: return "no cryptographic backend registered for this operation";
        case SDLS_ERR_CRYPTO_BACKEND_FAILED: return "the registered cryptographic backend reported failure";
        case SDLS_ERR_INVALID_ARGUMENT: return "invalid argument";
        default: return "unknown status";
    }
}
