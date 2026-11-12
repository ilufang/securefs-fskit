//
//  SFSConfigTests.m
//  securefsTests
//
//  Decrypts every lite format reference config of securefs' regression suite:
//  3 KDFs x 5 combinations of password and key file x padded/unpadded.
//

#import "SFSTestSupport.h"

#include "core/sfs_config_json.h"

@interface SFSConfigTests : XCTestCase
@end

@implementation SFSConfigTests

- (void)testAllReferenceConfigsDecrypt
{
    NSArray *kdfs = @[ @"scrypt", @"pkcs5-pbkdf2-hmac-sha256", @"argon2id" ];
    NSArray *modes = @[ @"PASSWORD", @"KEYFILE", @"KEYFILE2", @"PASSWORD_WITH_KEYFILE", @"PASSWORD_WITH_KEYFILE2" ];
    for (NSString *repo in @[ @"4", @"4-padded" ]) {
        for (NSString *kdf in kdfs) {
            for (NSString *mode in modes) {
                NSString *name = [NSString stringWithFormat:@".securefs.%@.%@.json", kdf, mode];
                NSString *path = [[SFSReferenceDirectory() stringByAppendingPathComponent:repo]
                    stringByAppendingPathComponent:name];
                sfs_params params;
                int err = SFSDecryptReferenceConfig(path, mode, &params);
                XCTAssertEqual(err, 0, @"%@/%@", repo, name);
                if (err) {
                    continue;
                }
                XCTAssertEqual(params.block_size, 4096u);
                XCTAssertEqual(params.iv_size, 12u);
                XCTAssertEqual(params.max_padding, [repo isEqualToString:@"4-padded"] ? 256u : 0u);
                XCTAssertEqual(params.has_padding_key, [repo isEqualToString:@"4-padded"]);
                XCTAssertEqual(params.long_name_threshold, 0u);
            }
        }
    }
}

- (void)testAllConfigsOfARepositoryShareKeys
{
    NSString *dir = [SFSReferenceDirectory() stringByAppendingPathComponent:@"4"];
    sfs_params a, b;
    XCTAssertEqual(SFSDecryptReferenceConfig([dir stringByAppendingPathComponent:@".securefs.scrypt.PASSWORD.json"], @"PASSWORD", &a), 0);
    XCTAssertEqual(SFSDecryptReferenceConfig([dir stringByAppendingPathComponent:@".securefs.argon2id.KEYFILE2.json"], @"KEYFILE2", &b), 0);
    XCTAssertEqual(memcmp(a.name_key, b.name_key, 32), 0);
    XCTAssertEqual(memcmp(a.content_key, b.content_key, 32), 0);
    XCTAssertEqual(memcmp(a.xattr_key, b.xattr_key, 32), 0);
}

- (void)testWrongSecretsAreRejected
{
    NSString *dir = [SFSReferenceDirectory() stringByAppendingPathComponent:@"4"];
    NSData *json = [NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:@".securefs.pkcs5-pbkdf2-hmac-sha256.PASSWORD.json"]];
    sfs_legacy_config config;
    XCTAssertEqual(sfs_legacy_config_parse_json(json.bytes, json.length, &config), 0);
    sfs_params params;
    XCTAssertEqual(sfs_legacy_config_decrypt(&config, (const uint8_t *)"abd", 3, NULL, 0, &params), EACCES);
    // A key file that wasn't used to create the config.
    XCTAssertEqual(sfs_legacy_config_decrypt(&config, (const uint8_t *)"abc", 3, (const uint8_t *)"x", 1, &params), EACCES);
    XCTAssertEqual(sfs_legacy_config_decrypt(&config, (const uint8_t *)"abc", 3, NULL, 0, &params), 0);
}

- (void)testFullFormatIsUnsupported
{
    NSString *path = [[SFSReferenceDirectory() stringByAppendingPathComponent:@"2"]
        stringByAppendingPathComponent:@".securefs.scrypt.PASSWORD.json"];
    sfs_params params;
    XCTAssertEqual(SFSDecryptReferenceConfig(path, @"PASSWORD", &params), ENOTSUP);
}

- (void)testMalformedConfigs
{
    sfs_legacy_config config;
    const char *bad[] = {
        "", "[]", "{}", "{\"version\": 4}",
        "{\"version\": 4, \"salt\": \"00\", \"encrypted_key\": {\"IV\": \"00\", \"MAC\": \"00\"}}",
        "{\"version\": \"4\", \"salt\": \"00\", \"encrypted_key\": {\"IV\": \"00\", \"MAC\": \"00\", \"key\": \"00\"}}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        XCTAssertEqual(sfs_legacy_config_parse_json(bad[i], strlen(bad[i]), &config), EINVAL, @"%s", bad[i]);
    }
    const char *odd_hex = "{\"version\": 4, \"iterations\": 1, \"salt\": \"0\", \"encrypted_key\": "
                          "{\"IV\": \"00\", \"MAC\": \"00\", \"key\": \"00\"}}";
    XCTAssertEqual(sfs_legacy_config_parse_json(odd_hex, strlen(odd_hex), &config), 0);
    sfs_params params;
    XCTAssertEqual(sfs_legacy_config_decrypt(&config, (const uint8_t *)"a", 1, NULL, 0, &params), EINVAL);
}

- (void)testDefaultsForMissingSizes
{
    // securefs defaults to a 4096 byte block and, for legacy configs, a 32 byte IV.
    const char *json = "{\"version\": 4, \"salt\": \"00\", \"encrypted_key\": {\"IV\": \"00\", \"MAC\": \"00\", \"key\": \"00\"}}";
    sfs_legacy_config config;
    XCTAssertEqual(sfs_legacy_config_parse_json(json, strlen(json), &config), 0);
    XCTAssertFalse(config.has_block_size);
    XCTAssertFalse(config.has_iv_size);
}

@end
