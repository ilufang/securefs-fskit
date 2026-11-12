//
//  SFSTestSupport.m
//  securefsTests
//

#import "SFSTestSupport.h"

#include "core/sfs_config_json.h"

NSString *const SFSReferencePassword = @"abc";

NSString *SFSReferenceDirectory(void)
{
    return [@SFS_SOURCE_ROOT stringByAppendingPathComponent:@".ref/securefs/test/reference"];
}

NSData *SFSDataFromHex(NSString *hex)
{
    NSMutableData *data = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
        unsigned value = 0;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&value];
        uint8_t byte = (uint8_t)value;
        [data appendBytes:&byte length:1];
    }
    return data;
}

NSString *SFSHexFromBytes(const void *bytes, size_t len)
{
    NSMutableString *s = [NSMutableString stringWithCapacity:len * 2];
    for (size_t i = 0; i < len; ++i) {
        [s appendFormat:@"%02x", ((const uint8_t *)bytes)[i]];
    }
    return s;
}

int SFSDecryptReferenceConfig(NSString *configPath, NSString *mode, sfs_params *out)
{
    NSData *json = [NSData dataWithContentsOfFile:configPath];
    if (!json) {
        return ENOENT;
    }
    sfs_legacy_config config;
    int err = sfs_legacy_config_parse_json(json.bytes, json.length, &config);
    if (err) {
        return err;
    }
    BOOL usesPassword = [mode hasPrefix:@"PASSWORD"];
    BOOL usesKeyfile = [mode containsString:@"KEYFILE"];
    NSData *password = [(usesPassword ? SFSReferencePassword : @SFS_KEYFILE_ONLY_PASSWORD)
        dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyfile = usesKeyfile
        ? [NSData dataWithContentsOfFile:[SFSReferenceDirectory() stringByAppendingPathComponent:@"keyfile"]]
        : nil;
    return sfs_legacy_config_decrypt(&config, password.bytes, password.length,
                                     keyfile ? keyfile.bytes : NULL, keyfile.length, out);
}

NSString *SFSMakeTemporaryDirectory(XCTestCase *testCase)
{
    NSString *path = [NSTemporaryDirectory()
        stringByAppendingPathComponent:[NSString stringWithFormat:@"sfs-test-%@", NSUUID.UUID.UUIDString]];
    [[NSFileManager defaultManager] createDirectoryAtPath:path
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:NULL];
    [testCase addTeardownBlock:^{
        [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
    }];
    return path;
}

sfs_params SFSTestParams(uint32_t blockSize, uint32_t ivSize, uint32_t maxPadding,
                         uint32_t longNameThreshold)
{
    sfs_params p;
    memset(&p, 0, sizeof(p));
    for (int i = 0; i < SFS_KEY_SIZE; ++i) {
        p.name_key[i] = (uint8_t)i;
        p.content_key[i] = (uint8_t)(0x40 + i);
        p.xattr_key[i] = (uint8_t)(0x80 + i);
        p.padding_key[i] = (uint8_t)(0xc0 + i);
    }
    p.has_padding_key = true;
    p.block_size = blockSize;
    p.iv_size = ivSize;
    p.max_padding = maxPadding;
    p.long_name_threshold = longNameThreshold;
    strlcpy(p.long_name_suffix, SFS_LEGACY_LONG_NAME_SUFFIX, sizeof(p.long_name_suffix));
    return p;
}
