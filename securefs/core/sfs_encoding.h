//
//  sfs_encoding.h
//  securefs
//
//  Text encodings used by securefs for encrypted names.
//

#ifndef SFS_ENCODING_H
#define SFS_ENCODING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Length of the base32 text for `len` bytes (no padding, no terminator).
static inline size_t sfs_base32_encoded_len(size_t len) { return (len * 8 + 4) / 5; }

/// Maximum number of bytes decoded from `len` characters.
static inline size_t sfs_base32_decoded_len(size_t len) { return len * 5 / 8; }

/// Encodes with securefs' base32 alphabet ("ABCDEFGHIJKMNPQRSTUVWXYZ23456789", no padding).
/// `out` must hold sfs_base32_encoded_len(len) + 1 bytes; the result is NUL terminated.
void sfs_base32_encode(const uint8_t *in, size_t len, char *out);

/// Decodes case-insensitively. `out` must hold sfs_base32_decoded_len(len) bytes.
/// Returns false if `in` contains a character outside the alphabet.
bool sfs_base32_decode(const char *in, size_t len, uint8_t *out, size_t *out_len);

/// URL-safe base64 without padding (absl::WebSafeBase64Escape). `out` must hold
/// (len + 2) / 3 * 4 + 1 bytes; the result is NUL terminated.
void sfs_base64url_encode(const uint8_t *in, size_t len, char *out);

/// Decodes URL-safe base64; padding is optional. `out` must hold len * 3 / 4 + 3 bytes.
bool sfs_base64url_decode(const char *in, size_t len, uint8_t *out, size_t *out_len);

/// Decodes an even-length hex string into exactly `out_len` bytes.
bool sfs_hex_decode(const char *in, size_t len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SFS_ENCODING_H */
