//
//  sfs_config_json.m
//  securefs
//

#import <Foundation/Foundation.h>

#include "sfs_config_json.h"

#include <errno.h>
#include <string.h>

static BOOL copy_string(NSDictionary *dict, NSString *key, char *out, size_t cap, BOOL required)
{
    id value = dict[key];
    if (value == nil || value == [NSNull null]) {
        out[0] = '\0';
        return !required;
    }
    if (![value isKindOfClass:[NSString class]]) {
        return NO;
    }
    const char *utf8 = [(NSString *)value UTF8String];
    if (utf8 == NULL || strlen(utf8) >= cap) {
        return NO;
    }
    strlcpy(out, utf8, cap);
    return YES;
}

static BOOL copy_uint(NSDictionary *dict, NSString *key, uint32_t *out, bool *present)
{
    id value = dict[key];
    if (value == nil || value == [NSNull null]) {
        if (present) {
            *present = false;
        }
        *out = 0;
        return YES;
    }
    if (![value isKindOfClass:[NSNumber class]]) {
        return NO;
    }
    long long v = [(NSNumber *)value longLongValue];
    if (v < 0 || v > UINT32_MAX) {
        return NO;
    }
    *out = (uint32_t)v;
    if (present) {
        *present = true;
    }
    return YES;
}

int sfs_legacy_config_parse_json(const void *data, size_t len, sfs_legacy_config *out)
{
    @autoreleasepool {
        memset(out, 0, sizeof(*out));
        NSData *json = [NSData dataWithBytesNoCopy:(void *)data length:len freeWhenDone:NO];
        id root = [NSJSONSerialization JSONObjectWithData:json options:0 error:NULL];
        if (![root isKindOfClass:[NSDictionary class]]) {
            return EINVAL;
        }
        NSDictionary *dict = root;
        NSDictionary *key = dict[@"encrypted_key"];
        if (![key isKindOfClass:[NSDictionary class]]) {
            return EINVAL;
        }
        bool version_present = false;
        BOOL ok = copy_uint(dict, @"version", &out->version, &version_present)
            && copy_uint(dict, @"block_size", &out->block_size, &out->has_block_size)
            && copy_uint(dict, @"iv_size", &out->iv_size, &out->has_iv_size)
            && copy_string(dict, @"salt", out->salt_hex, sizeof(out->salt_hex), YES)
            && copy_string(key, @"IV", out->key_iv_hex, sizeof(out->key_iv_hex), YES)
            && copy_string(key, @"MAC", out->key_mac_hex, sizeof(out->key_mac_hex), YES)
            && copy_string(key, @"key", out->key_ciphertext_hex, sizeof(out->key_ciphertext_hex),
                           YES)
            && copy_uint(dict, @"iterations", &out->iterations, NULL)
            && copy_string(dict, @"pbkdf", out->pbkdf, sizeof(out->pbkdf), NO)
            && copy_uint(dict, @"scrypt_r", &out->scrypt_r, NULL)
            && copy_uint(dict, @"scrypt_p", &out->scrypt_p, NULL)
            && copy_uint(dict, @"argon2_m_cost", &out->argon2_m_cost, NULL)
            && copy_uint(dict, @"argon2_p", &out->argon2_p, NULL)
            && copy_uint(dict, @"max_padding", &out->max_padding, NULL);
        if (!ok || !version_present) {
            return EINVAL;
        }
        id long_name = dict[@"long_name_component"];
        if ([long_name isKindOfClass:[NSNumber class]]) {
            out->long_name_component = [(NSNumber *)long_name boolValue];
        }
        return 0;
    }
}
