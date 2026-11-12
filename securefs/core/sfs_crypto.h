//
//  sfs_crypto.h
//  securefs
//
//  Thin wrappers over OpenSSL's libcrypto for the primitives used by the
//  securefs lite format. No cryptographic algorithm is implemented here;
//  these functions only adapt OpenSSL's EVP interfaces to the calling
//  conventions used by the rest of the core.
//

#ifndef SFS_CRYPTO_H
#define SFS_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SFS_KEY_SIZE 32
#define SFS_SIV_SIZE 16
#define SFS_GCM_TAG_SIZE 16

/// Initializes libcrypto without loading any openssl.cnf (the extension is sandboxed).
/// Safe to call multiple times. Returns false if OpenSSL could not provide every
/// algorithm securefs needs.
bool sfs_crypto_init(void);

/// Fills `buf` with cryptographically secure random bytes.
void sfs_random(void *buf, size_t len);

/// Overwrites memory in a way the compiler won't optimize away.
void sfs_secure_zero(void *buf, size_t len);

/// Constant-time comparison.
bool sfs_constant_time_equal(const void *a, const void *b, size_t len);

#pragma mark - AES-GCM

/// A reusable AES-GCM context bound to one key and one IV length.
/// Not thread safe; callers serialize access.
typedef struct sfs_gcm sfs_gcm;

/// Creates a GCM context. `key_len` must be 16 or 32. Returns NULL on failure.
sfs_gcm *sfs_gcm_new(const uint8_t *key, size_t key_len, size_t iv_len);
void sfs_gcm_free(sfs_gcm *gcm);

/// Encrypts `len` bytes from `in` into `out` and writes a 16-byte tag.
bool sfs_gcm_encrypt(sfs_gcm *gcm, const uint8_t *iv,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t len,
                     uint8_t *out, uint8_t tag[SFS_GCM_TAG_SIZE]);

/// Decrypts `len` bytes and verifies the 16-byte tag. The plaintext is always
/// written to `out`; the return value reports whether the tag was valid.
bool sfs_gcm_decrypt(sfs_gcm *gcm, const uint8_t *iv,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t len,
                     const uint8_t tag[SFS_GCM_TAG_SIZE], uint8_t *out);

#pragma mark - AES-SIV (RFC 5297)

/// AES-SIV with a 32-byte key (AES-128 for both S2V/CMAC and CTR, as securefs does)
/// and no associated data. `len` must be > 0.
bool sfs_siv_encrypt(const uint8_t key[SFS_KEY_SIZE], const uint8_t *in, size_t len,
                     uint8_t siv[SFS_SIV_SIZE], uint8_t *out);
bool sfs_siv_decrypt(const uint8_t key[SFS_KEY_SIZE], const uint8_t siv[SFS_SIV_SIZE],
                     const uint8_t *in, size_t len, uint8_t *out);

#pragma mark - Block cipher / MAC / hash

/// Encrypts a single 16-byte block with AES-256 in ECB mode.
bool sfs_aes256_ecb_block(const uint8_t key[SFS_KEY_SIZE], const uint8_t in[16], uint8_t out[16]);

/// HMAC-SHA256 producing 32 bytes.
bool sfs_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[32]);

/// Keyed BLAKE2b with a 32-byte digest.
bool sfs_blake2b_keyed_32(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                          uint8_t out[32]);

#pragma mark - Password based key derivation (all produce `out_len` bytes)

bool sfs_pbkdf2_hmac_sha256(const uint8_t *pass, size_t pass_len, const uint8_t *salt,
                            size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len);
bool sfs_scrypt(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                uint64_t n, uint32_t r, uint32_t p, uint8_t *out, size_t out_len);
bool sfs_argon2id(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                  uint32_t time_cost, uint32_t memory_cost_kib, uint32_t parallelism,
                  uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SFS_CRYPTO_H */
