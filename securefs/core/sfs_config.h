//
//  sfs_config.h
//  securefs
//
//  Repository parameters and decryption of the legacy `.securefs.json` config
//  (lite format, version 4). Ported from securefs' params_io.cpp.
//

#ifndef SFS_CONFIG_H
#define SFS_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sfs_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SFS_LEGACY_CONFIG_FILE_NAME ".securefs.json"
#define SFS_LONG_NAME_TABLE_FILE_NAME ".long_names.db"
#define SFS_LEGACY_LONG_NAME_SUFFIX "..."
#define SFS_MAX_LONG_NAME_SUFFIX 32

/// Decrypted parameters of a lite format repository.
typedef struct sfs_params {
    uint8_t name_key[SFS_KEY_SIZE];
    uint8_t content_key[SFS_KEY_SIZE];
    uint8_t xattr_key[SFS_KEY_SIZE];
    uint8_t padding_key[SFS_KEY_SIZE];
    bool has_padding_key;
    uint32_t block_size;
    uint32_t iv_size;
    uint32_t max_padding;
    /// 0 selects the legacy name scheme without long name support.
    uint32_t long_name_threshold;
    char long_name_suffix[SFS_MAX_LONG_NAME_SUFFIX];
} sfs_params;

/// The fields of `.securefs.json` (protobuf message LegacySecurefsJsonParams).
/// Hex fields are kept as text and decoded during decryption.
typedef struct sfs_legacy_config {
    uint32_t version;
    bool has_block_size;
    uint32_t block_size;
    bool has_iv_size;
    uint32_t iv_size;
    char salt_hex[256];
    char key_iv_hex[256];
    char key_mac_hex[64];
    char key_ciphertext_hex[512];
    uint32_t iterations;
    char pbkdf[64];
    uint32_t scrypt_r;
    uint32_t scrypt_p;
    uint32_t argon2_m_cost;
    uint32_t argon2_p;
    uint32_t max_padding;
    bool long_name_component;
} sfs_legacy_config;

/// The password used by securefs when only a key file is supplied.
#define SFS_KEYFILE_ONLY_PASSWORD " "

/// Decrypts the master keys.
///
/// - Parameters:
///   - keyfile: Contents of the key file, or NULL when no key file is used.
/// - Returns: 0 on success, EACCES if the password/key file is wrong, ENOTSUP for
///   non-lite formats or unknown KDFs, EINVAL for malformed configs, ENOMEM if the
///   key derivation could not run.
int sfs_legacy_config_decrypt(const sfs_legacy_config *config, const uint8_t *password,
                              size_t password_len, const uint8_t *keyfile, size_t keyfile_len,
                              sfs_params *out);

/// Validates block/iv sizes (as securefs' AESGCMCryptStream constructor does).
bool sfs_params_valid(const sfs_params *params);

#ifdef __cplusplus
}
#endif

#endif /* SFS_CONFIG_H */
