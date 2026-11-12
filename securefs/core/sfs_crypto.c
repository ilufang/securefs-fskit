//
//  sfs_crypto.c
//  securefs
//
//  OpenSSL adapters. See sfs_crypto.h.
//

#include "sfs_crypto.h"

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/thread.h>

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static bool g_init_ok = false;
static EVP_CIPHER *g_siv_cipher = NULL;
static EVP_MAC *g_blake2b_mac = NULL;
static EVP_KDF *g_argon2id_kdf = NULL;
static EVP_KDF *g_scrypt_kdf = NULL;
static uint64_t g_argon2_max_threads = 1;

static void sfs_crypto_init_once(void)
{
    // The extension is sandboxed and must not try to read OpenSSL's configuration file.
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
        return;
    }
    g_siv_cipher = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
    g_blake2b_mac = EVP_MAC_fetch(NULL, "BLAKE2BMAC", NULL);
    g_argon2id_kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    g_scrypt_kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    // Argon2 lanes can be computed in parallel if OpenSSL's thread pool is enabled.
    if (OSSL_set_max_threads(NULL, 8) == 1) {
        g_argon2_max_threads = 8;
    }
    g_init_ok = g_siv_cipher && g_blake2b_mac && g_argon2id_kdf && g_scrypt_kdf;
}

bool sfs_crypto_init(void)
{
    pthread_once(&g_init_once, sfs_crypto_init_once);
    return g_init_ok;
}

void sfs_random(void *buf, size_t len)
{
    arc4random_buf(buf, len);
}

void sfs_secure_zero(void *buf, size_t len)
{
    if (buf && len) {
        OPENSSL_cleanse(buf, len);
    }
}

bool sfs_constant_time_equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

#pragma mark - AES-GCM

struct sfs_gcm {
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
};

static bool gcm_prepare(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const uint8_t *key,
                        size_t iv_len, bool encrypt)
{
    int (*init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *,
                const unsigned char *) = encrypt ? EVP_EncryptInit_ex : EVP_DecryptInit_ex;
    if (init(ctx, cipher, NULL, NULL, NULL) != 1) {
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) {
        return false;
    }
    // The key is retained by the context; each operation then only sets a fresh IV.
    return init(ctx, NULL, NULL, key, NULL) == 1;
}

sfs_gcm *sfs_gcm_new(const uint8_t *key, size_t key_len, size_t iv_len)
{
    if (!sfs_crypto_init()) {
        return NULL;
    }
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) {
        cipher = EVP_aes_128_gcm();
    } else if (key_len == 32) {
        cipher = EVP_aes_256_gcm();
    } else {
        return NULL;
    }
    if (iv_len == 0 || iv_len > 64) {
        return NULL;
    }
    sfs_gcm *gcm = calloc(1, sizeof(*gcm));
    if (!gcm) {
        return NULL;
    }
    gcm->enc = EVP_CIPHER_CTX_new();
    gcm->dec = EVP_CIPHER_CTX_new();
    if (!gcm->enc || !gcm->dec || !gcm_prepare(gcm->enc, cipher, key, iv_len, true)
        || !gcm_prepare(gcm->dec, cipher, key, iv_len, false)) {
        sfs_gcm_free(gcm);
        return NULL;
    }
    return gcm;
}

void sfs_gcm_free(sfs_gcm *gcm)
{
    if (!gcm) {
        return;
    }
    EVP_CIPHER_CTX_free(gcm->enc);
    EVP_CIPHER_CTX_free(gcm->dec);
    free(gcm);
}

bool sfs_gcm_encrypt(sfs_gcm *gcm, const uint8_t *iv, const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[SFS_GCM_TAG_SIZE])
{
    int outl = 0;
    if (len > INT_MAX || aad_len > INT_MAX) {
        return false;
    }
    if (EVP_EncryptInit_ex(gcm->enc, NULL, NULL, NULL, iv) != 1) {
        return false;
    }
    if (aad_len > 0 && EVP_EncryptUpdate(gcm->enc, NULL, &outl, aad, (int)aad_len) != 1) {
        return false;
    }
    if (len > 0 && EVP_EncryptUpdate(gcm->enc, out, &outl, in, (int)len) != 1) {
        return false;
    }
    if (EVP_EncryptFinal_ex(gcm->enc, out + (len > 0 ? outl : 0), &outl) != 1) {
        return false;
    }
    return EVP_CIPHER_CTX_ctrl(gcm->enc, EVP_CTRL_GCM_GET_TAG, SFS_GCM_TAG_SIZE, tag) == 1;
}

bool sfs_gcm_decrypt(sfs_gcm *gcm, const uint8_t *iv, const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t len, const uint8_t tag[SFS_GCM_TAG_SIZE],
                     uint8_t *out)
{
    int outl = 0;
    if (len > INT_MAX || aad_len > INT_MAX) {
        return false;
    }
    if (EVP_DecryptInit_ex(gcm->dec, NULL, NULL, NULL, iv) != 1) {
        return false;
    }
    if (aad_len > 0 && EVP_DecryptUpdate(gcm->dec, NULL, &outl, aad, (int)aad_len) != 1) {
        return false;
    }
    if (len > 0 && EVP_DecryptUpdate(gcm->dec, out, &outl, in, (int)len) != 1) {
        return false;
    }
    uint8_t tag_copy[SFS_GCM_TAG_SIZE];
    memcpy(tag_copy, tag, sizeof(tag_copy));
    if (EVP_CIPHER_CTX_ctrl(gcm->dec, EVP_CTRL_GCM_SET_TAG, SFS_GCM_TAG_SIZE, tag_copy) != 1) {
        return false;
    }
    uint8_t final_block[16];
    return EVP_DecryptFinal_ex(gcm->dec, final_block, &outl) == 1;
}

#pragma mark - AES-SIV

bool sfs_siv_encrypt(const uint8_t key[SFS_KEY_SIZE], const uint8_t *in, size_t len,
                     uint8_t siv[SFS_SIV_SIZE], uint8_t *out)
{
    if (!sfs_crypto_init() || len == 0 || len > INT_MAX) {
        return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    int outl = 0, finl = 0;
    bool ok = EVP_EncryptInit_ex2(ctx, g_siv_cipher, key, NULL, NULL) == 1
        && EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) == 1
        && EVP_EncryptFinal_ex(ctx, out + outl, &finl) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SFS_SIV_SIZE, siv) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool sfs_siv_decrypt(const uint8_t key[SFS_KEY_SIZE], const uint8_t siv[SFS_SIV_SIZE],
                     const uint8_t *in, size_t len, uint8_t *out)
{
    if (!sfs_crypto_init() || len == 0 || len > INT_MAX) {
        return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    uint8_t tag[SFS_SIV_SIZE];
    memcpy(tag, siv, sizeof(tag));
    int outl = 0, finl = 0;
    bool ok = EVP_DecryptInit_ex2(ctx, g_siv_cipher, key, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SFS_SIV_SIZE, tag) == 1
        && EVP_DecryptUpdate(ctx, out, &outl, in, (int)len) == 1
        && EVP_DecryptFinal_ex(ctx, out + outl, &finl) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

#pragma mark - Block cipher / MAC / hash

bool sfs_aes256_ecb_block(const uint8_t key[SFS_KEY_SIZE], const uint8_t in[16], uint8_t out[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    int outl = 0, finl = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_EncryptUpdate(ctx, out, &outl, in, 16) == 1
        && EVP_EncryptFinal_ex(ctx, out + outl, &finl) == 1 && outl + finl == 16;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool sfs_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[32])
{
    if (key_len > INT_MAX) {
        return false;
    }
    unsigned int outl = 0;
    static const uint8_t empty = 0;
    return HMAC(EVP_sha256(), key, (int)key_len, msg ? msg : &empty, msg_len, out, &outl) != NULL
        && outl == 32;
}

bool sfs_blake2b_keyed_32(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                          uint8_t out[32])
{
    if (!sfs_crypto_init()) {
        return false;
    }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(g_blake2b_mac);
    if (!ctx) {
        return false;
    }
    size_t digest_size = 32, outl = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &digest_size),
        OSSL_PARAM_construct_end(),
    };
    bool ok = EVP_MAC_init(ctx, key, key_len, params) == 1
        && EVP_MAC_update(ctx, msg, msg_len) == 1 && EVP_MAC_final(ctx, out, &outl, 32) == 1
        && outl == 32;
    EVP_MAC_CTX_free(ctx);
    return ok;
}

#pragma mark - Password based key derivation

bool sfs_pbkdf2_hmac_sha256(const uint8_t *pass, size_t pass_len, const uint8_t *salt,
                            size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
    if (pass_len > INT_MAX || salt_len > INT_MAX || out_len > INT_MAX || iterations == 0
        || iterations > INT_MAX) {
        return false;
    }
    return PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len, salt, (int)salt_len,
                             (int)iterations, EVP_sha256(), (int)out_len, out)
        == 1;
}

bool sfs_scrypt(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                uint64_t n, uint32_t r, uint32_t p, uint8_t *out, size_t out_len)
{
    if (!sfs_crypto_init()) {
        return false;
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(g_scrypt_kdf);
    if (!ctx) {
        return false;
    }
    // OpenSSL refuses to use more than 32 MiB by default; securefs commonly uses N=2^18, r=8
    // (256 MiB), so allow what the parameters require plus headroom.
    uint64_t maxmem = 128ULL * r * (n + p + 2) + (16ULL << 20);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pass, pass_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
        OSSL_PARAM_construct_end(),
    };
    bool ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

bool sfs_argon2id(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
                  uint32_t time_cost, uint32_t memory_cost_kib, uint32_t parallelism,
                  uint8_t *out, size_t out_len)
{
    if (!sfs_crypto_init()) {
        return false;
    }
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(g_argon2id_kdf);
    if (!ctx) {
        return false;
    }
    uint32_t threads = parallelism;
    if (threads > g_argon2_max_threads) {
        threads = (uint32_t)g_argon2_max_threads;
    }
    if (threads == 0) {
        threads = 1;
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pass, pass_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &time_cost),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_cost_kib),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &parallelism),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_end(),
    };
    bool ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
    EVP_KDF_CTX_free(ctx);
    return ok;
}
