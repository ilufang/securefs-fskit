//
//  sfs_xattr.c
//  securefs
//

#include "sfs_xattr.h"
#include "sfs_crypto.h"
#include "sfs_encoding.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int sfs_xattr_encrypt_name(const sfs_params *params, const char *name, size_t len, char *out,
                           size_t cap)
{
    if (len == 0) {
        return EINVAL;
    }
    size_t raw_len = SFS_SIV_SIZE + len;
    size_t prefix_len = strlen(SFS_XATTR_NAME_PREFIX);
    if (prefix_len + (raw_len + 2) / 3 * 4 + 1 > cap) {
        return ERANGE;
    }
    uint8_t *raw = malloc(raw_len);
    if (!raw) {
        return ENOMEM;
    }
    int err = 0;
    if (sfs_siv_encrypt(params->xattr_key, (const uint8_t *)name, len, raw, raw + SFS_SIV_SIZE)) {
        memcpy(out, SFS_XATTR_NAME_PREFIX, prefix_len);
        sfs_base64url_encode(raw, raw_len, out + prefix_len);
    } else {
        err = EIO;
    }
    free(raw);
    return err;
}

bool sfs_xattr_decrypt_name(const sfs_params *params, const char *enc, size_t len, char *out,
                            size_t cap, size_t *out_len)
{
    size_t prefix_len = strlen(SFS_XATTR_NAME_PREFIX);
    if (len <= prefix_len || memcmp(enc, SFS_XATTR_NAME_PREFIX, prefix_len) != 0) {
        return false;
    }
    enc += prefix_len;
    len -= prefix_len;
    uint8_t *raw = malloc(len * 3 / 4 + 3);
    if (!raw) {
        return false;
    }
    size_t raw_len = 0;
    bool ok = sfs_base64url_decode(enc, len, raw, &raw_len) && raw_len > SFS_SIV_SIZE
        && raw_len - SFS_SIV_SIZE < cap
        && sfs_siv_decrypt(params->xattr_key, raw, raw + SFS_SIV_SIZE, raw_len - SFS_SIV_SIZE,
                           (uint8_t *)out);
    if (ok) {
        *out_len = raw_len - SFS_SIV_SIZE;
        out[*out_len] = '\0';
    }
    free(raw);
    return ok;
}

int sfs_xattr_encrypt_value(const sfs_params *params, const void *in, size_t len, uint8_t *out)
{
    sfs_gcm *gcm = sfs_gcm_new(params->xattr_key, SFS_KEY_SIZE, params->iv_size);
    if (!gcm) {
        return ENOMEM;
    }
    sfs_random(out, params->iv_size);
    bool ok = sfs_gcm_encrypt(gcm, out, NULL, 0, in, len, out + params->iv_size,
                              out + params->iv_size + len);
    sfs_gcm_free(gcm);
    return ok ? 0 : EIO;
}

int sfs_xattr_decrypt_value(const sfs_params *params, bool verify, const uint8_t *in, size_t len,
                            uint8_t *out, size_t *out_len)
{
    size_t overhead = params->iv_size + SFS_GCM_TAG_SIZE;
    if (len < overhead) {
        return EINVAL;
    }
    sfs_gcm *gcm = sfs_gcm_new(params->xattr_key, SFS_KEY_SIZE, params->iv_size);
    if (!gcm) {
        return ENOMEM;
    }
    size_t plain_len = len - overhead;
    bool ok = sfs_gcm_decrypt(gcm, in, NULL, 0, in + params->iv_size, plain_len,
                              in + len - SFS_GCM_TAG_SIZE, out);
    sfs_gcm_free(gcm);
    if (!ok && verify) {
        return EIO;
    }
    *out_len = plain_len;
    return 0;
}
