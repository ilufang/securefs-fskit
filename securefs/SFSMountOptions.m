//
//  SFSMountOptions.m
//  securefs
//

#import "SFSMountOptions.h"

#import <FSKit/FSKit.h>
#include <errno.h>

#include "core/sfs_crypto.h"

@implementation SFSMountOptions

+ (instancetype)optionsWithTaskOptions:(NSArray<NSString *> *)taskOptions error:(NSError **)error
{
    SFSMountOptions *options = [[SFSMountOptions alloc] init];
    options.verify = YES;
    options.xattr = YES;
    options.normalizeNFC = YES;
    options.uidOverride = -1;
    options.gidOverride = -1;
    if (![options mergeTaskOptions:taskOptions error:error]) {
        return nil;
    }
    return options;
}

static BOOL parseID(NSString *value, int64_t *out)
{
    NSScanner *scanner = [NSScanner scannerWithString:value];
    long long v = 0;
    if (![scanner scanLongLong:&v] || !scanner.isAtEnd || v < -1 || v > UINT32_MAX) {
        return NO;
    }
    *out = v;
    return YES;
}

- (BOOL)applyKey:(NSString *)key value:(nullable NSString *)value error:(NSError **)error
{
    NSString *k = key.lowercaseString;
    BOOL needsValue = NO;
    if ([k isEqualToString:@"password"] || [k isEqualToString:@"pass"]) {
        needsValue = YES;
        if (value) {
            self.password = [[value dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        }
    } else if ([k isEqualToString:@"keyfile"]) {
        needsValue = YES;
        self.keyfilePath = value.stringByExpandingTildeInPath;
    } else if ([k isEqualToString:@"keydata"]) {
        needsValue = YES;
        if (value) {
            NSData *data = [[NSData alloc] initWithBase64EncodedString:value options:0];
            if (!data) {
                goto invalid;
            }
            self.keyfileData = [data mutableCopy];
        }
    } else if ([k isEqualToString:@"config"]) {
        needsValue = YES;
        self.configPath = value.stringByExpandingTildeInPath;
    } else if ([k isEqualToString:@"ro"] || [k isEqualToString:@"rdonly"]) {
        self.readOnly = YES;
    } else if ([k isEqualToString:@"rw"]) {
        self.readOnly = NO;
    } else if ([k isEqualToString:@"insecure"]) {
        self.verify = NO;
    } else if ([k isEqualToString:@"noxattr"]) {
        self.xattr = NO;
    } else if ([k isEqualToString:@"plaintextnames"]) {
        self.plaintextNames = YES;
    } else if ([k isEqualToString:@"normalization"]) {
        needsValue = YES;
        if ([value isEqualToString:@"none"]) {
            self.normalizeNFC = NO;
        } else if ([value isEqualToString:@"nfc"]) {
            self.normalizeNFC = YES;
        } else if (value) {
            // Case folding isn't supported: Foundation's folding differs from the Unicode
            // full case folding securefs uses, which would produce different names.
            goto invalid;
        }
    } else if ([k isEqualToString:@"uid"]) {
        needsValue = YES;
        if (value && !parseID(value, &_uidOverride)) {
            goto invalid;
        }
    } else if ([k isEqualToString:@"gid"]) {
        needsValue = YES;
        if (value && !parseID(value, &_gidOverride)) {
            goto invalid;
        }
    }
    // Unknown options (generic mount options such as nobrowse) are ignored here.
    if (needsValue && value == nil) {
        goto invalid;
    }
    return YES;

invalid:
    if (error) {
        *error = fs_errorForPOSIXError(EINVAL);
    }
    return NO;
}

- (BOOL)applyOptionList:(NSString *)list error:(NSError **)error
{
    for (NSString *component in [list componentsSeparatedByString:@","]) {
        if (component.length == 0) {
            continue;
        }
        NSRange eq = [component rangeOfString:@"="];
        NSString *key = eq.location == NSNotFound ? component
                                                  : [component substringToIndex:eq.location];
        NSString *value = nil;
        if (eq.location != NSNotFound) {
            NSString *raw = [component substringFromIndex:eq.location + 1];
            value = raw.stringByRemovingPercentEncoding ?: raw;
        }
        if (![self applyKey:key value:value error:error]) {
            return NO;
        }
    }
    return YES;
}

- (BOOL)mergeTaskOptions:(NSArray<NSString *> *)taskOptions error:(NSError **)error
{
    for (NSUInteger i = 0; i < taskOptions.count; ++i) {
        NSString *opt = taskOptions[i];
        if ([opt isEqualToString:@"-o"]) {
            if (i + 1 < taskOptions.count
                && ![self applyOptionList:taskOptions[++i] error:error]) {
                return NO;
            }
        } else if ([opt hasPrefix:@"-o"]) {
            if (![self applyOptionList:[opt substringFromIndex:2] error:error]) {
                return NO;
            }
        } else if ([opt isEqualToString:@"--rdonly"] || [opt isEqualToString:@"-r"]) {
            self.readOnly = YES;
        } else if ([opt isEqualToString:@"-f"]) {
            self.force = YES;
        }
    }
    return YES;
}

- (BOOL)hasSecrets
{
    return self.password != nil || self.keyfileData != nil || self.keyfilePath != nil;
}

+ (NSString *)redactedDescriptionOfTaskOptions:(NSArray<NSString *> *)taskOptions
{
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithCapacity:taskOptions.count];
    for (NSString *opt in taskOptions) {
        NSMutableArray<NSString *> *parts = [NSMutableArray array];
        for (NSString *component in [opt componentsSeparatedByString:@","]) {
            NSRange eq = [component rangeOfString:@"="];
            NSString *key = eq.location == NSNotFound ? component : [component substringToIndex:eq.location];
            NSString *k = [key.lowercaseString stringByReplacingOccurrencesOfString:@"-o" withString:@""];
            BOOL secret = [k isEqualToString:@"password"] || [k isEqualToString:@"pass"]
                || [k isEqualToString:@"keydata"];
            [parts addObject:secret ? [key stringByAppendingString:@"=<redacted>"] : component];
        }
        [out addObject:[parts componentsJoinedByString:@","]];
    }
    return [NSString stringWithFormat:@"[%@]", [out componentsJoinedByString:@" | "]];
}

- (void)clearSecrets
{
    // The secrets are stored as NSMutableData so they can be wiped in place. Copies made by
    // FSKit when transporting the options are outside of our control.
    for (NSData *secret in @[ self.password ?: [NSData data], self.keyfileData ?: [NSData data] ]) {
        if ([secret isKindOfClass:[NSMutableData class]]) {
            sfs_secure_zero(((NSMutableData *)secret).mutableBytes, secret.length);
        }
    }
    _password = nil;
    _keyfileData = nil;
}

@end
