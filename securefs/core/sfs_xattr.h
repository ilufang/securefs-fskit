//
//  sfs_xattr.h
//  securefs
//
//  Extended attribute encryption of the lite format (securefs' generic_xattr and
//  XattrCryptor): the underlying name is "user." + base64url(SIV || AES-SIV(name))
//  using the xattr key, and the value is IV || AES-256-GCM(value) || tag.
//

#ifndef SFS_XATTR_H
#define SFS_XATTR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sfs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SFS_XATTR_NAME_PREFIX "user."

/// Encrypts an attribute name into `out` (NUL terminated). Returns 0, EINVAL or ERANGE.
int sfs_xattr_encrypt_name(const sfs_params *params, const char *name, size_t len, char *out,
                           size_t cap);

/// Decrypts an underlying attribute name. Returns false for names securefs didn't create.
bool sfs_xattr_decrypt_name(const sfs_params *params, const char *enc, size_t len, char *out,
                            size_t cap, size_t *out_len);

static inline size_t sfs_xattr_encrypted_size(const sfs_params *params, size_t len)
{
    return len + params->iv_size + 16;
}

/// `out` must hold sfs_xattr_encrypted_size(len) bytes.
int sfs_xattr_encrypt_value(const sfs_params *params, const void *in, size_t len, uint8_t *out);

/// Decrypts into `out` (which must hold `len` bytes). Returns 0, EIO (verification
/// failure, only when `verify`), or EINVAL for truncated data.
int sfs_xattr_decrypt_value(const sfs_params *params, bool verify, const uint8_t *in, size_t len,
                            uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SFS_XATTR_H */
