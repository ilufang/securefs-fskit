//
//  sfs_config.c
//  securefs
//

#include "sfs_config.h"
#include "sfs_encoding.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const sfs_legacy_config *config;
    uint8_t iv[128];
    size_t iv_len;
    uint8_t mac[SFS_GCM_TAG_SIZE];
    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t master_key[256];
} unwrap_state;

/// Runs the configured password-based KDF. Returns 0, ENOTSUP or ENOMEM.
static int derive_password_key(const sfs_legacy_config *config, const uint8_t *password,
                               size_t password_len, const uint8_t *salt, size_t salt_len,
                               uint8_t out[SFS_KEY_SIZE])
{
    bool ok;
    if (strcmp(config->pbkdf, "argon2id") == 0) {
        ok = sfs_argon2id(password, password_len, salt, salt_len, config->iterations,
                          config->argon2_m_cost, config->argon2_p, out, SFS_KEY_SIZE);
    } else if (strcmp(config->pbkdf, "scrypt") == 0) {
        ok = sfs_scrypt(password, password_len, salt, salt_len, config->iterations,
                        config->scrypt_r, config->scrypt_p, out, SFS_KEY_SIZE);
    } else if (strcmp(config->pbkdf, "pkcs5-pbkdf2-hmac-sha256") == 0 || config->pbkdf[0] == 0) {
        ok = sfs_pbkdf2_hmac_sha256(password, password_len, salt, salt_len, config->iterations,
                                    out, SFS_KEY_SIZE);
    } else {
        return ENOTSUP;
    }
    return ok ? 0 : ENOMEM;
}

/// Attempts to unwrap the master key with a candidate wrapping key.
static bool try_unwrap(unwrap_state *st, const uint8_t wrapping_key[SFS_KEY_SIZE])
{
    // securefs authenticates the format version as associated data.
    const char *header = "version=4";
    sfs_gcm *gcm = sfs_gcm_new(wrapping_key, SFS_KEY_SIZE, st->iv_len);
    if (!gcm) {
        return false;
    }
    bool ok = sfs_gcm_decrypt(gcm, st->iv, (const uint8_t *)header, strlen(header),
                              st->ciphertext, st->ciphertext_len, st->mac, st->master_key);
    sfs_gcm_free(gcm);
    return ok;
}

static bool decode_hex_field(const char *hex, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > cap) {
        return false;
    }
    *out_len = len / 2;
    return sfs_hex_decode(hex, len, out, *out_len);
}

int sfs_legacy_config_decrypt(const sfs_legacy_config *config, const uint8_t *password,
                              size_t password_len, const uint8_t *keyfile, size_t keyfile_len,
                              sfs_params *out)
{
    if (!sfs_crypto_init()) {
        return ENOMEM;
    }
    if (config->version != 4) {
        // Versions 1-3 are the full format, which this implementation doesn't support.
        return ENOTSUP;
    }

    int rc = EINVAL;
    unwrap_state *st = calloc(1, sizeof(*st));
    if (!st) {
        return ENOMEM;
    }
    st->config = config;
    uint8_t salt[128];
    size_t salt_len = 0, mac_len = 0;
    uint8_t derived[SFS_KEY_SIZE], effective_salt[SFS_KEY_SIZE], candidate[SFS_KEY_SIZE];

    if (!decode_hex_field(config->salt_hex, salt, sizeof(salt), &salt_len)
        || !decode_hex_field(config->key_iv_hex, st->iv, sizeof(st->iv), &st->iv_len)
        || !decode_hex_field(config->key_mac_hex, st->mac, sizeof(st->mac), &mac_len)
        || !decode_hex_field(config->key_ciphertext_hex, st->ciphertext, sizeof(st->ciphertext),
                             &st->ciphertext_len)
        || mac_len != SFS_GCM_TAG_SIZE || st->iv_len == 0) {
        goto done;
    }

    bool success = false;
    if (keyfile == NULL) {
        rc = derive_password_key(config, password, password_len, salt, salt_len, derived);
        if (rc != 0) {
            goto done;
        }
        success = try_unwrap(st, derived);
    } else {
        // securefs has used two ways of mixing in a key file; try both in sequence.
        // 1. The salt is replaced by HMAC-SHA256(key=salt, message=keyfile).
        if (!sfs_hmac_sha256(salt, salt_len, keyfile, keyfile_len, effective_salt)) {
            rc = ENOMEM;
            goto done;
        }
        rc = derive_password_key(config, password, password_len, effective_salt,
                                 sizeof(effective_salt), derived);
        if (rc != 0) {
            goto done;
        }
        success = try_unwrap(st, derived);
        if (!success) {
            // 2. The derived key is post-processed by HMAC-SHA256(key=derived, message=keyfile).
            rc = derive_password_key(config, password, password_len, salt, salt_len, derived);
            if (rc != 0) {
                goto done;
            }
            if (!sfs_hmac_sha256(derived, sizeof(derived), keyfile, keyfile_len, candidate)) {
                rc = ENOMEM;
                goto done;
            }
            success = try_unwrap(st, candidate);
        }
    }
    if (!success) {
        rc = EACCES;
        goto done;
    }

    if (st->ciphertext_len != 3 * SFS_KEY_SIZE && st->ciphertext_len != 4 * SFS_KEY_SIZE) {
        rc = EINVAL;
        goto done;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->name_key, st->master_key, SFS_KEY_SIZE);
    memcpy(out->content_key, st->master_key + SFS_KEY_SIZE, SFS_KEY_SIZE);
    memcpy(out->xattr_key, st->master_key + 2 * SFS_KEY_SIZE, SFS_KEY_SIZE);
    if (st->ciphertext_len == 4 * SFS_KEY_SIZE) {
        memcpy(out->padding_key, st->master_key + 3 * SFS_KEY_SIZE, SFS_KEY_SIZE);
        out->has_padding_key = true;
    }
    out->block_size = config->has_block_size ? config->block_size : 4096;
    out->iv_size = config->has_iv_size ? config->iv_size : 32;
    out->max_padding = config->max_padding;
    if (config->long_name_component) {
        out->long_name_threshold = 128;
    }
    // An empty suffix means the legacy "..." suffix.
    strlcpy(out->long_name_suffix, SFS_LEGACY_LONG_NAME_SUFFIX, sizeof(out->long_name_suffix));

    if (!sfs_params_valid(out)) {
        sfs_secure_zero(out, sizeof(*out));
        rc = EINVAL;
        goto done;
    }
    rc = 0;

done:
    sfs_secure_zero(derived, sizeof(derived));
    sfs_secure_zero(candidate, sizeof(candidate));
    sfs_secure_zero(st, sizeof(*st));
    free(st);
    return rc;
}

bool sfs_params_valid(const sfs_params *params)
{
    if (params->iv_size < 12 || params->iv_size > 32) {
        return false;
    }
    if (params->block_size < 32 || params->block_size > (64u << 20)) {
        return false;
    }
    if (params->max_padding > 0 && !params->has_padding_key) {
        return false;
    }
    return true;
}
