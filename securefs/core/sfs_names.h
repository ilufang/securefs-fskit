//
//  sfs_names.h
//  securefs
//
//  File name and symlink target encryption of the lite format. Ported from the
//  name translators in securefs' lite_format.cpp:
//
//  - Legacy (no long name support): component -> base32(SIV || AES-SIV(component)).
//  - New style (long_name_threshold > 0): components longer than the threshold are
//    stored as base32(SIV || AES-SIV(BLAKE2b_keyed(component))) + suffix, and the
//    encrypted full name is kept in the directory's `.long_names.db`.
//  - Plain text names: no transformation.
//
//  Names are NFC-normalized before encryption by default (securefs' macOS default),
//  so that lookups are insensitive to the normalization form used by the caller.
//

#ifndef SFS_NAMES_H
#define SFS_NAMES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sfs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Large enough for any encrypted component the core produces.
#define SFS_MAX_ENCRYPTED_COMPONENT 4096

typedef enum sfs_name_kind {
    SFS_NAME_DECRYPTED = 0,
    /// The name isn't a valid encrypted name (e.g. a foreign file); skip it.
    SFS_NAME_INVALID = 1,
    /// The real name is stored in the long name table.
    SFS_NAME_LONG = 2,
} sfs_name_kind;

typedef struct sfs_names {
    uint8_t key[SFS_KEY_SIZE];
    uint32_t long_name_threshold;
    char long_name_suffix[SFS_MAX_LONG_NAME_SUFFIX];
    bool plaintext;
    bool normalize_nfc;
} sfs_names;

void sfs_names_init(sfs_names *names, const sfs_params *params, bool plaintext,
                    bool normalize_nfc);

/// Encrypts one path component (no '/').
///
/// - Parameters:
///   - out: Receives the underlying (on-disk) name, NUL terminated.
///   - long_full: When the component is a long name, receives the encrypted full name
///     to store in the long name table. May be NULL if the caller doesn't need it.
///   - is_long: Set to whether the component is a long name.
/// - Returns: 0, EINVAL, or ENAMETOOLONG.
int sfs_names_encrypt_component(const sfs_names *names, const char *name, size_t len, char *out,
                                size_t cap, char *long_full, size_t long_cap, bool *is_long);

/// Decrypts one underlying component. `out` receives the plaintext name, NUL terminated.
sfs_name_kind sfs_names_decrypt_component(const sfs_names *names, const char *enc, size_t len,
                                          char *out, size_t cap, size_t *out_len);

/// Whether an underlying name in a directory is internal to securefs and never listed.
bool sfs_names_is_hidden_underlying(const sfs_names *names, const char *name, size_t len);

/// Encrypts a symlink target. `*out` is malloc'ed and NUL terminated.
int sfs_names_encrypt_symlink(const sfs_names *names, const char *target, size_t len, char **out,
                              size_t *out_len);

/// Decrypts a symlink target. `*out` is malloc'ed and NUL terminated.
int sfs_names_decrypt_symlink(const sfs_names *names, const char *enc, size_t len, char **out,
                              size_t *out_len);

/// The longest plaintext component that fits in `physical_max` underlying bytes.
uint32_t sfs_names_max_component_length(const sfs_names *names, uint32_t physical_max);

#ifdef __cplusplus
}
#endif

#endif /* SFS_NAMES_H */
