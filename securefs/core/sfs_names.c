//
//  sfs_names.c
//  securefs
//

#include "sfs_names.h"
#include "sfs_crypto.h"
#include "sfs_encoding.h"

#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/// securefs' legacy translator refuses components longer than this.
static const size_t kLegacyMaxComponent = 2000;
/// New style symlink targets are split into '/'-separated chunks of this many bytes.
static const size_t kSymlinkChunk = 60;

void sfs_names_init(sfs_names *names, const sfs_params *params, bool plaintext,
                    bool normalize_nfc)
{
    memset(names, 0, sizeof(*names));
    memcpy(names->key, params->name_key, SFS_KEY_SIZE);
    names->long_name_threshold = params->long_name_threshold;
    strlcpy(names->long_name_suffix,
            params->long_name_suffix[0] ? params->long_name_suffix : SFS_LEGACY_LONG_NAME_SUFFIX,
            sizeof(names->long_name_suffix));
    names->plaintext = plaintext;
    names->normalize_nfc = normalize_nfc && !plaintext;
}

/// Returns a malloc'ed NFC form of `name`, or NULL if it isn't valid UTF-8 (in which case
/// securefs falls back to the raw bytes).
static char *nfc_normalize(const char *name, size_t len, size_t *out_len)
{
    CFStringRef str = CFStringCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)name,
                                              (CFIndex)len, kCFStringEncodingUTF8, false);
    if (!str) {
        return NULL;
    }
    CFMutableStringRef mutable = CFStringCreateMutableCopy(kCFAllocatorDefault, 0, str);
    CFRelease(str);
    if (!mutable) {
        return NULL;
    }
    CFStringNormalize(mutable, kCFStringNormalizationFormC);
    CFIndex length = CFStringGetLength(mutable), used = 0;
    CFStringGetBytes(mutable, CFRangeMake(0, length), kCFStringEncodingUTF8, 0, false, NULL, 0,
                     &used);
    char *result = malloc((size_t)used + 1);
    if (result) {
        CFStringGetBytes(mutable, CFRangeMake(0, length), kCFStringEncodingUTF8, 0, false,
                         (UInt8 *)result, used, &used);
        result[used] = '\0';
        *out_len = (size_t)used;
    }
    CFRelease(mutable);
    return result;
}

/// base32(SIV || AES-SIV(data)) into `out`.
static int siv_base32(const sfs_names *names, const uint8_t *data, size_t len, char *out,
                      size_t cap)
{
    if (len == 0) {
        return EINVAL;
    }
    size_t raw_len = SFS_SIV_SIZE + len;
    if (sfs_base32_encoded_len(raw_len) + 1 > cap) {
        return ENAMETOOLONG;
    }
    uint8_t *raw = malloc(raw_len);
    if (!raw) {
        return ENOMEM;
    }
    int err = 0;
    if (sfs_siv_encrypt(names->key, data, len, raw, raw + SFS_SIV_SIZE)) {
        sfs_base32_encode(raw, raw_len, out);
    } else {
        err = EIO;
    }
    free(raw);
    return err;
}

/// Decodes base32(SIV || ciphertext) and decrypts it. Returns false if invalid.
static bool base32_siv_decrypt(const sfs_names *names, const char *enc, size_t len, char *out,
                               size_t cap, size_t *out_len)
{
    size_t decoded_cap = sfs_base32_decoded_len(len), decoded_len = 0;
    if (decoded_cap <= SFS_SIV_SIZE) {
        return false;
    }
    uint8_t *decoded = malloc(decoded_cap);
    if (!decoded) {
        return false;
    }
    bool ok = sfs_base32_decode(enc, len, decoded, &decoded_len) && decoded_len > SFS_SIV_SIZE
        && decoded_len - SFS_SIV_SIZE < cap
        && sfs_siv_decrypt(names->key, decoded, decoded + SFS_SIV_SIZE,
                           decoded_len - SFS_SIV_SIZE, (uint8_t *)out);
    if (ok) {
        *out_len = decoded_len - SFS_SIV_SIZE;
        out[*out_len] = '\0';
    }
    free(decoded);
    return ok;
}

int sfs_names_encrypt_component(const sfs_names *names, const char *name, size_t len, char *out,
                                size_t cap, char *long_full, size_t long_cap, bool *is_long)
{
    *is_long = false;
    if (len == 0 || memchr(name, '/', len) || memchr(name, '\0', len)) {
        return EINVAL;
    }
    if (names->plaintext) {
        if (len + 1 > cap) {
            return ENAMETOOLONG;
        }
        memcpy(out, name, len);
        out[len] = '\0';
        return 0;
    }

    size_t normalized_len = 0;
    char *normalized = names->normalize_nfc ? nfc_normalize(name, len, &normalized_len) : NULL;
    if (normalized) {
        name = normalized;
        len = normalized_len;
    }

    int err;
    if (names->long_name_threshold == 0) {
        err = len > kLegacyMaxComponent
            ? ENAMETOOLONG
            : siv_base32(names, (const uint8_t *)name, len, out, cap);
    } else if (len <= names->long_name_threshold) {
        err = siv_base32(names, (const uint8_t *)name, len, out, cap);
    } else {
        // Long name: the on-disk name is derived from a keyed hash of the real name.
        uint8_t digest[32];
        if (!sfs_blake2b_keyed_32(names->key, SFS_KEY_SIZE, (const uint8_t *)name, len, digest)) {
            err = EIO;
        } else {
            err = siv_base32(names, digest, sizeof(digest), out, cap);
        }
        if (!err) {
            size_t used = strlen(out);
            if (used + strlen(names->long_name_suffix) + 1 > cap) {
                err = ENAMETOOLONG;
            } else {
                strlcat(out, names->long_name_suffix, cap);
                *is_long = true;
            }
        }
        if (!err && long_full) {
            err = siv_base32(names, (const uint8_t *)name, len, long_full, long_cap);
        }
    }
    free(normalized);
    return err;
}

static bool has_suffix(const char *s, size_t len, const char *suffix)
{
    size_t slen = strlen(suffix);
    return slen > 0 && len >= slen && memcmp(s + len - slen, suffix, slen) == 0;
}

sfs_name_kind sfs_names_decrypt_component(const sfs_names *names, const char *enc, size_t len,
                                          char *out, size_t cap, size_t *out_len)
{
    if (names->plaintext) {
        if (len + 1 > cap) {
            return SFS_NAME_INVALID;
        }
        memcpy(out, enc, len);
        out[len] = '\0';
        *out_len = len;
        return SFS_NAME_DECRYPTED;
    }
    if (names->long_name_threshold > 0 && has_suffix(enc, len, names->long_name_suffix)) {
        return SFS_NAME_LONG;
    }
    return base32_siv_decrypt(names, enc, len, out, cap, out_len) ? SFS_NAME_DECRYPTED
                                                                  : SFS_NAME_INVALID;
}

bool sfs_names_is_hidden_underlying(const sfs_names *names, const char *name, size_t len)
{
    if (len == 0 || (len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.')) {
        return true;
    }
    if (names->plaintext) {
        // Plain text repositories still keep securefs' own files private.
        static const char *const internal[] = {
            SFS_LEGACY_CONFIG_FILE_NAME, ".config.pb", SFS_LONG_NAME_TABLE_FILE_NAME,
            ".long_names.db-journal", ".securefs.lock",
        };
        for (size_t i = 0; i < sizeof(internal) / sizeof(internal[0]); ++i) {
            if (strlen(internal[i]) == len && memcmp(internal[i], name, len) == 0) {
                return true;
            }
        }
        return false;
    }
    // Encrypted names never start with '.', so dot files are securefs' own or foreign.
    return name[0] == '.';
}

#pragma mark - Symlinks

/// Growable string buffer.
typedef struct {
    char *data;
    size_t len, cap;
} strbuf;

static bool strbuf_append(strbuf *b, const char *s, size_t len)
{
    if (b->len + len + 1 > b->cap) {
        size_t cap = (b->len + len + 1) * 2;
        char *p = realloc(b->data, cap);
        if (!p) {
            return false;
        }
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, s, len);
    b->len += len;
    b->data[b->len] = '\0';
    return true;
}

static int finish(strbuf *b, int err, char **out, size_t *out_len)
{
    if (err) {
        free(b->data);
        return err;
    }
    if (!b->data && !strbuf_append(b, "", 0)) {
        return ENOMEM;
    }
    *out = b->data;
    *out_len = b->len;
    return 0;
}

/// Legacy: each '/'-separated component is encrypted independently; separators are kept.
static int legacy_encrypt_symlink(const sfs_names *names, const char *path, size_t len,
                                  char **out, size_t *out_len)
{
    strbuf b = {0};
    if (len == 1 && path[0] == '/') {
        return finish(&b, strbuf_append(&b, ".", 1) ? 0 : ENOMEM, out, out_len);
    }
    char *part = malloc(SFS_MAX_ENCRYPTED_COMPONENT);
    if (!part) {
        return ENOMEM;
    }
    int err = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len && !err; ++i) {
        if (i == len || path[i] == '/') {
            if (i > start) {
                if (i - start > kLegacyMaxComponent) {
                    err = ENAMETOOLONG;
                    break;
                }
                err = siv_base32(names, (const uint8_t *)path + start, i - start, part,
                                 SFS_MAX_ENCRYPTED_COMPONENT);
                if (!err && !strbuf_append(&b, part, strlen(part))) {
                    err = ENOMEM;
                }
            }
            if (!err && i < len && !strbuf_append(&b, "/", 1)) {
                err = ENOMEM;
            }
            start = i + 1;
        }
    }
    free(part);
    return finish(&b, err, out, out_len);
}

static int legacy_decrypt_symlink(const sfs_names *names, const char *path, size_t len,
                                  char **out, size_t *out_len)
{
    strbuf b = {0};
    if (len == 1 && path[0] == '.') {
        return finish(&b, strbuf_append(&b, "/", 1) ? 0 : ENOMEM, out, out_len);
    }
    char *part = malloc(SFS_MAX_ENCRYPTED_COMPONENT);
    if (!part) {
        return ENOMEM;
    }
    int err = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len && !err; ++i) {
        if (i == len || path[i] == '/') {
            if (i > start) {
                size_t part_len = 0;
                if (!base32_siv_decrypt(names, path + start, i - start, part,
                                        SFS_MAX_ENCRYPTED_COMPONENT, &part_len)) {
                    err = EIO;
                    break;
                }
                if (!strbuf_append(&b, part, part_len)) {
                    err = ENOMEM;
                }
            }
            if (!err && i < len && !strbuf_append(&b, "/", 1)) {
                err = ENOMEM;
            }
            start = i + 1;
        }
    }
    free(part);
    return finish(&b, err, out, out_len);
}

/// New style: the whole target is encrypted at once and split into short components.
static int new_encrypt_symlink(const sfs_names *names, const char *path, size_t len, char **out,
                               size_t *out_len)
{
    strbuf b = {0};
    size_t raw_len = SFS_SIV_SIZE + len;
    uint8_t *raw = malloc(raw_len);
    char part[128];
    if (!raw) {
        return ENOMEM;
    }
    int err = sfs_siv_encrypt(names->key, (const uint8_t *)path, len, raw, raw + SFS_SIV_SIZE)
        ? 0
        : EIO;
    for (size_t i = 0; i < raw_len && !err; i += kSymlinkChunk) {
        size_t n = raw_len - i < kSymlinkChunk ? raw_len - i : kSymlinkChunk;
        sfs_base32_encode(raw + i, n, part);
        if (!strbuf_append(&b, "/", 1) || !strbuf_append(&b, part, strlen(part))) {
            err = ENOMEM;
        }
    }
    free(raw);
    return finish(&b, err, out, out_len);
}

static int new_decrypt_symlink(const sfs_names *names, const char *path, size_t len, char **out,
                               size_t *out_len)
{
    char *joined = malloc(len + 1);
    char *result = malloc(len + 1);
    if (!joined || !result) {
        free(joined);
        free(result);
        return ENOMEM;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        if (path[i] != '/') {
            joined[j++] = path[i];
        }
    }
    size_t result_len = 0;
    bool ok = base32_siv_decrypt(names, joined, j, result, len + 1, &result_len);
    free(joined);
    if (!ok) {
        free(result);
        return EIO;
    }
    *out = result;
    *out_len = result_len;
    return 0;
}

int sfs_names_encrypt_symlink(const sfs_names *names, const char *target, size_t len, char **out,
                              size_t *out_len)
{
    if (len == 0 || memchr(target, '\0', len)) {
        return EINVAL;
    }
    if (names->plaintext) {
        strbuf b = {0};
        return finish(&b, strbuf_append(&b, target, len) ? 0 : ENOMEM, out, out_len);
    }
    return names->long_name_threshold > 0 ? new_encrypt_symlink(names, target, len, out, out_len)
                                          : legacy_encrypt_symlink(names, target, len, out, out_len);
}

int sfs_names_decrypt_symlink(const sfs_names *names, const char *enc, size_t len, char **out,
                              size_t *out_len)
{
    if (len == 0) {
        return EIO;
    }
    if (names->plaintext) {
        strbuf b = {0};
        return finish(&b, strbuf_append(&b, enc, len) ? 0 : ENOMEM, out, out_len);
    }
    return names->long_name_threshold > 0 ? new_decrypt_symlink(names, enc, len, out, out_len)
                                          : legacy_decrypt_symlink(names, enc, len, out, out_len);
}

uint32_t sfs_names_max_component_length(const sfs_names *names, uint32_t physical_max)
{
    if (names->plaintext) {
        return physical_max;
    }
    if (names->long_name_threshold == 0) {
        if (physical_max <= SFS_SIV_SIZE * 8 / 5) {
            return 0;
        }
        return physical_max * 5 / 8 - SFS_SIV_SIZE;
    }
    if (physical_max <= (names->long_name_threshold + SFS_SIV_SIZE) * 8 / 5) {
        return physical_max * 5 / 8 - SFS_SIV_SIZE;
    }
    return 65535;
}
