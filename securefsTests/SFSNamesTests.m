//
//  SFSNamesTests.m
//  securefsTests
//
//  Name and symlink encryption, normalization, long names, xattrs and the
//  long name table.
//

#import "SFSTestSupport.h"

#include "core/sfs_longname.h"
#include "core/sfs_names.h"
#include "core/sfs_xattr.h"

@interface SFSNamesTests : XCTestCase
@end

@implementation SFSNamesTests

- (NSString *)encrypt:(NSString *)name with:(const sfs_names *)names isLong:(bool *)isLong full:(NSString **)full
{
    const char *utf8 = name.UTF8String;
    char out[SFS_MAX_ENCRYPTED_COMPONENT], longFull[SFS_MAX_ENCRYPTED_COMPONENT];
    bool l = false;
    longFull[0] = '\0';
    int err = sfs_names_encrypt_component(names, utf8, strlen(utf8), out, sizeof(out), longFull, sizeof(longFull), &l);
    if (err) {
        return nil;
    }
    if (isLong) {
        *isLong = l;
    }
    if (full) {
        *full = @(longFull);
    }
    return @(out);
}

- (NSString *)decrypt:(NSString *)enc with:(const sfs_names *)names kind:(sfs_name_kind *)kind
{
    char out[SFS_MAX_ENCRYPTED_COMPONENT];
    size_t len = 0;
    sfs_name_kind k = sfs_names_decrypt_component(names, enc.UTF8String, strlen(enc.UTF8String), out, sizeof(out), &len);
    if (kind) {
        *kind = k;
    }
    return k == SFS_NAME_DECRYPTED ? [[NSString alloc] initWithBytes:out length:len encoding:NSUTF8StringEncoding] : nil;
}

- (void)testLegacyRoundTrip
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    sfs_names names;
    sfs_names_init(&names, &params, false, true);
    for (NSString *name in @[ @"a", @"hello.txt", @"加密式文件系统", @"🌱🅾️⛎®️ ♍️", @".DS_Store", @"x y" ]) {
        NSString *enc = [self encrypt:name with:&names isLong:NULL full:NULL];
        XCTAssertNotNil(enc);
        XCTAssertFalse([enc hasPrefix:@"."], @"encrypted names never look hidden");
        XCTAssertEqualObjects([self decrypt:enc with:&names kind:NULL], name);
        // Deterministic.
        XCTAssertEqualObjects([self encrypt:name with:&names isLong:NULL full:NULL], enc);
        // Base32 decoding is case insensitive.
        XCTAssertEqualObjects([self decrypt:enc.lowercaseString with:&names kind:NULL], name);
    }
    sfs_name_kind kind;
    XCTAssertNil([self decrypt:@"NOTANENCRYPTEDNAME23456789ABCDEFGHIJKM" with:&names kind:&kind]);
    XCTAssertEqual(kind, SFS_NAME_INVALID);
    XCTAssertNil([self decrypt:@"lol.txt" with:&names kind:&kind]);
    XCTAssertEqual(kind, SFS_NAME_INVALID);
}

- (void)testNormalization
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    sfs_names nfc, raw;
    sfs_names_init(&nfc, &params, false, true);
    sfs_names_init(&raw, &params, false, false);
    NSString *composed = @"\u00e4.bin", *decomposed = @"a\u0308.bin";
    XCTAssertEqualObjects([self encrypt:composed with:&nfc isLong:NULL full:NULL],
                          [self encrypt:decomposed with:&nfc isLong:NULL full:NULL]);
    XCTAssertNotEqualObjects([self encrypt:composed with:&raw isLong:NULL full:NULL],
                             [self encrypt:decomposed with:&raw isLong:NULL full:NULL]);
    XCTAssertEqualObjects([self encrypt:composed with:&raw isLong:NULL full:NULL],
                          [self encrypt:composed with:&nfc isLong:NULL full:NULL]);
}

- (void)testInvalidComponents
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    sfs_names names;
    sfs_names_init(&names, &params, false, true);
    char out[64];
    bool l;
    XCTAssertEqual(sfs_names_encrypt_component(&names, "a/b", 3, out, sizeof(out), NULL, 0, &l), EINVAL);
    XCTAssertEqual(sfs_names_encrypt_component(&names, "", 0, out, sizeof(out), NULL, 0, &l), EINVAL);
    XCTAssertEqual(sfs_names_encrypt_component(&names, "a long name", 11, out, 8, NULL, 0, &l), ENAMETOOLONG);
}

- (void)testLongNames
{
    sfs_params params = SFSTestParams(4096, 12, 0, 128);
    sfs_names names;
    sfs_names_init(&names, &params, false, true);
    bool isLong = true;
    NSString *full = nil;
    NSString *shortName = [@"" stringByPaddingToLength:128 withString:@"s" startingAtIndex:0];
    NSString *enc = [self encrypt:shortName with:&names isLong:&isLong full:&full];
    XCTAssertFalse(isLong);
    XCTAssertEqualObjects([self decrypt:enc with:&names kind:NULL], shortName);

    NSString *longName = [@"" stringByPaddingToLength:217 withString:@"k" startingAtIndex:0];
    enc = [self encrypt:longName with:&names isLong:&isLong full:&full];
    XCTAssertTrue(isLong);
    XCTAssertTrue([enc hasSuffix:@"..."]);
    XCTAssertLessThan(enc.length, 100u);
    sfs_name_kind kind;
    XCTAssertNil([self decrypt:enc with:&names kind:&kind]);
    XCTAssertEqual(kind, SFS_NAME_LONG);
    // The table stores the encrypted full name, which decrypts normally.
    XCTAssertEqualObjects([self decrypt:full with:&names kind:NULL], longName);
    XCTAssertEqual(sfs_names_max_component_length(&names, 255), 65535u);

    sfs_names legacy;
    sfs_params legacyParams = SFSTestParams(4096, 12, 0, 0);
    sfs_names_init(&legacy, &legacyParams, false, true);
    XCTAssertEqual(sfs_names_max_component_length(&legacy, 255), 255u * 5 / 8 - 16);
}

- (void)checkSymlinksWithThreshold:(uint32_t)threshold
{
    sfs_params params = SFSTestParams(4096, 12, 0, threshold);
    sfs_names names;
    sfs_names_init(&names, &params, false, true);
    NSArray *targets = @[ @"/", @"/etc/hosts", @"relative/path", @"../up//double/", @"a", @"é/ü",
                          [@"" stringByPaddingToLength:300 withString:@"long/" startingAtIndex:0] ];
    for (NSString *target in targets) {
        const char *t = target.UTF8String;
        char *enc = NULL, *back = NULL;
        size_t encLen = 0, backLen = 0;
        XCTAssertEqual(sfs_names_encrypt_symlink(&names, t, strlen(t), &enc, &encLen), 0, @"%@", target);
        XCTAssertEqual(strlen(enc), encLen);
        XCTAssertEqual(sfs_names_decrypt_symlink(&names, enc, encLen, &back, &backLen), 0, @"%@", target);
        XCTAssertEqualObjects([[NSString alloc] initWithBytes:back length:backLen encoding:NSUTF8StringEncoding], target);
        if (threshold > 0) {
            // New style targets are split into short components.
            for (NSString *component in [@(enc) componentsSeparatedByString:@"/"]) {
                XCTAssertLessThanOrEqual(component.length, 96u);
            }
        }
        free(enc);
        free(back);
    }
}

- (void)testLegacySymlinks
{
    [self checkSymlinksWithThreshold:0];
}

- (void)testNewStyleSymlinks
{
    [self checkSymlinksWithThreshold:128];
}

- (void)testPlainTextNames
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    sfs_names names;
    sfs_names_init(&names, &params, true, true);
    XCTAssertEqualObjects([self encrypt:@"ä" with:&names isLong:NULL full:NULL], @"ä");
    XCTAssertTrue(sfs_names_is_hidden_underlying(&names, ".securefs.json", 14));
    XCTAssertTrue(sfs_names_is_hidden_underlying(&names, ".long_names.db", 14));
    XCTAssertFalse(sfs_names_is_hidden_underlying(&names, ".DS_Store", 9));
    sfs_names encrypted;
    sfs_names_init(&encrypted, &params, false, true);
    XCTAssertTrue(sfs_names_is_hidden_underlying(&encrypted, ".DS_Store", 9));
    XCTAssertTrue(sfs_names_is_hidden_underlying(&encrypted, "..", 2));
}

- (void)testXattrNamesAndValues
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    char enc[512], plain[512];
    size_t len = 0;
    XCTAssertEqual(sfs_xattr_encrypt_name(&params, "com.apple.FinderInfo", 20, enc, sizeof(enc)), 0);
    XCTAssertTrue(strncmp(enc, "user.", 5) == 0);
    // URL-safe base64 without padding, as securefs writes it.
    XCTAssertEqual([@(enc) rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"+/="]].location, NSNotFound);
    XCTAssertTrue(sfs_xattr_decrypt_name(&params, enc, strlen(enc), plain, sizeof(plain), &len));
    XCTAssertEqualObjects([[NSString alloc] initWithBytes:plain length:len encoding:NSUTF8StringEncoding], @"com.apple.FinderInfo");
    XCTAssertFalse(sfs_xattr_decrypt_name(&params, "com.apple.quarantine", 20, plain, sizeof(plain), &len));
    XCTAssertFalse(sfs_xattr_decrypt_name(&params, "user.AAAA", 9, plain, sizeof(plain), &len));

    for (size_t n = 0; n < 40; n += 13) {
        uint8_t value[40], out[80], back[40];
        arc4random_buf(value, n);
        XCTAssertEqual(sfs_xattr_encrypted_size(&params, n), n + 28);
        XCTAssertEqual(sfs_xattr_encrypt_value(&params, value, n, out), 0);
        size_t backLen = 99;
        XCTAssertEqual(sfs_xattr_decrypt_value(&params, true, out, n + 28, back, &backLen), 0);
        XCTAssertEqual(backLen, n);
        XCTAssertEqual(memcmp(back, value, n), 0);
        out[n + 27] ^= 1;
        XCTAssertEqual(sfs_xattr_decrypt_value(&params, true, out, n + 28, back, &backLen), EIO);
        XCTAssertEqual(sfs_xattr_decrypt_value(&params, false, out, n + 28, back, &backLen), 0);
    }
    uint8_t back[4];
    size_t backLen;
    XCTAssertEqual(sfs_xattr_decrypt_value(&params, true, (const uint8_t *)"short", 5, back, &backLen), EINVAL);
}

- (void)testLongNameTable
{
    NSString *dir = SFSMakeTemporaryDirectory(self);
    NSString *a = [dir stringByAppendingPathComponent:@"a.db"], *b = [dir stringByAppendingPathComponent:@"b.db"];
    char out[256];
    XCTAssertEqual(sfs_longname_lookup(a.fileSystemRepresentation, "h1...", out, sizeof(out)), ENOENT);

    sfs_longname_txn *txn = NULL;
    XCTAssertEqual(sfs_longname_begin(a.fileSystemRepresentation, NULL, &txn), 0);
    XCTAssertEqual(sfs_longname_insert(txn, false, "h1...", "FULL1"), 0);
    XCTAssertEqual(sfs_longname_end(txn, true), 0);
    XCTAssertEqual(sfs_longname_lookup(a.fileSystemRepresentation, "h1...", out, sizeof(out)), 0);
    XCTAssertEqualObjects(@(out), @"FULL1");
    XCTAssertEqual(sfs_longname_lookup(a.fileSystemRepresentation, "h2...", out, sizeof(out)), ENOENT);

    // Rolled back changes don't persist.
    XCTAssertEqual(sfs_longname_begin(a.fileSystemRepresentation, NULL, &txn), 0);
    XCTAssertEqual(sfs_longname_remove(txn, "h1..."), 0);
    XCTAssertEqual(sfs_longname_end(txn, false), 0);
    XCTAssertEqual(sfs_longname_lookup(a.fileSystemRepresentation, "h1...", out, sizeof(out)), 0);

    // Rename across directories updates both tables in one transaction.
    XCTAssertEqual(sfs_longname_begin(a.fileSystemRepresentation, b.fileSystemRepresentation, &txn), 0);
    XCTAssertEqual(sfs_longname_remove(txn, "h1..."), 0);
    XCTAssertEqual(sfs_longname_insert(txn, true, "h3...", "FULL3"), 0);
    XCTAssertEqual(sfs_longname_end(txn, true), 0);
    XCTAssertEqual(sfs_longname_lookup(a.fileSystemRepresentation, "h1...", out, sizeof(out)), ENOENT);
    XCTAssertEqual(sfs_longname_lookup(b.fileSystemRepresentation, "h3...", out, sizeof(out)), 0);
    XCTAssertEqualObjects(@(out), @"FULL3");

    // Same table on both sides.
    XCTAssertEqual(sfs_longname_begin(b.fileSystemRepresentation, b.fileSystemRepresentation, &txn), 0);
    XCTAssertEqual(sfs_longname_remove(txn, "h3..."), 0);
    XCTAssertEqual(sfs_longname_insert(txn, true, "h4...", "FULL4"), 0);
    XCTAssertEqual(sfs_longname_end(txn, true), 0);
    XCTAssertEqual(sfs_longname_lookup(b.fileSystemRepresentation, "h4...", out, sizeof(out)), 0);
}

@end
