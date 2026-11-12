//
//  SFSCryptoTests.m
//  securefsTests
//
//  Known-answer tests for the OpenSSL adapters and the text encodings.
//

#import "SFSTestSupport.h"

#include "core/sfs_crypto.h"
#include "core/sfs_encoding.h"

@interface SFSCryptoTests : XCTestCase
@end

@implementation SFSCryptoTests

- (void)setUp
{
    XCTAssertTrue(sfs_crypto_init());
}

- (void)testGCMKnownAnswers
{
    // Test cases 1 and 2 of the GCM specification (McGrew & Viega): zero key and IV.
    uint8_t key[16] = {0}, iv[12] = {0}, zeros[16] = {0}, out[16], tag[16];
    sfs_gcm *gcm = sfs_gcm_new(key, sizeof(key), sizeof(iv));
    XCTAssertTrue(gcm != NULL);
    XCTAssertTrue(sfs_gcm_encrypt(gcm, iv, NULL, 0, NULL, 0, out, tag));
    XCTAssertEqualObjects(SFSHexFromBytes(tag, 16), @"58e2fccefa7e3061367f1d57a4e7455a");
    XCTAssertTrue(sfs_gcm_encrypt(gcm, iv, NULL, 0, zeros, 16, out, tag));
    XCTAssertEqualObjects(SFSHexFromBytes(out, 16), @"0388dace60b6a392f328c2b971b2fe78");
    XCTAssertEqualObjects(SFSHexFromBytes(tag, 16), @"ab6e47d42cec13bdf53a67b21257bddf");

    uint8_t back[16];
    XCTAssertTrue(sfs_gcm_decrypt(gcm, iv, NULL, 0, out, 16, tag, back));
    XCTAssertEqual(memcmp(back, zeros, 16), 0);
    tag[0] ^= 1;
    XCTAssertFalse(sfs_gcm_decrypt(gcm, iv, NULL, 0, out, 16, tag, back));
    sfs_gcm_free(gcm);
}

- (void)testGCMLongIVAndAssociatedDataRoundTrip
{
    // securefs wraps the master key with a 32-byte IV and authenticates "version=4".
    uint8_t key[32], iv[32], msg[100], ct[100], tag[16], back[100];
    sfs_random(key, sizeof(key));
    sfs_random(iv, sizeof(iv));
    sfs_random(msg, sizeof(msg));
    sfs_gcm *gcm = sfs_gcm_new(key, 32, 32);
    const uint8_t aad[] = "version=4";
    XCTAssertTrue(sfs_gcm_encrypt(gcm, iv, aad, 9, msg, sizeof(msg), ct, tag));
    XCTAssertTrue(sfs_gcm_decrypt(gcm, iv, aad, 9, ct, sizeof(ct), tag, back));
    XCTAssertEqual(memcmp(back, msg, sizeof(msg)), 0);
    XCTAssertFalse(sfs_gcm_decrypt(gcm, iv, aad, 8, ct, sizeof(ct), tag, back));
    sfs_gcm_free(gcm);
}

- (void)testSIVIsDeterministicAndAuthenticated
{
    uint8_t key[32], ct[20], ct2[20], siv[16], siv2[16], back[20];
    sfs_random(key, sizeof(key));
    const char *msg = "a file name.txt.....";
    XCTAssertTrue(sfs_siv_encrypt(key, (const uint8_t *)msg, 20, siv, ct));
    XCTAssertTrue(sfs_siv_encrypt(key, (const uint8_t *)msg, 20, siv2, ct2));
    XCTAssertEqual(memcmp(siv, siv2, 16), 0);
    XCTAssertEqual(memcmp(ct, ct2, 20), 0);
    XCTAssertTrue(sfs_siv_decrypt(key, siv, ct, 20, back));
    XCTAssertEqual(memcmp(back, msg, 20), 0);
    ct[3] ^= 0x10;
    XCTAssertFalse(sfs_siv_decrypt(key, siv, ct, 20, back));
}

- (void)testPBKDF2KnownAnswer
{
    uint8_t out[32];
    XCTAssertTrue(sfs_pbkdf2_hmac_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, out, 32));
    XCTAssertEqualObjects(SFSHexFromBytes(out, 32),
                          @"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
}

- (void)testScryptKnownAnswer
{
    // RFC 7914, section 12.
    uint8_t out[64];
    XCTAssertTrue(sfs_scrypt((const uint8_t *)"password", 8, (const uint8_t *)"NaCl", 4, 1024, 8, 16, out, 64));
    XCTAssertEqualObjects(SFSHexFromBytes(out, 64),
                          @"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
                          @"2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
}

- (void)testScryptAllowsLargeMemoryCost
{
    // Repositories created with securefs' defaults use N = 2^18, r = 8 (256 MiB), which is
    // above OpenSSL's default memory limit.
    uint8_t out[32];
    XCTAssertTrue(sfs_scrypt((const uint8_t *)"x", 1, (const uint8_t *)"salt", 4, 1 << 18, 8, 1, out, 32));
}

- (void)testBlake2bKeyedKnownAnswer
{
    // Expected values from Python's hashlib.blake2b(msg, key=bytes(range(32)), digest_size=32).
    uint8_t key[32], out[32];
    for (int i = 0; i < 32; ++i) {
        key[i] = (uint8_t)i;
    }
    char msg[217];
    memset(msg, 'k', sizeof(msg));
    XCTAssertTrue(sfs_blake2b_keyed_32(key, 32, (const uint8_t *)msg, sizeof(msg), out));
    XCTAssertEqualObjects(SFSHexFromBytes(out, 32),
                          @"e345470131e554609e5b0bbd612c9911f2469a2c538145365cc38f2958b5f99f");
    XCTAssertTrue(sfs_blake2b_keyed_32(key, 32, (const uint8_t *)"", 0, out));
    XCTAssertEqualObjects(SFSHexFromBytes(out, 32),
                          @"4e51e7a913fc80137da52880fecca175bf81e117d5c68126dc2774033517ea0d");
}

- (void)testArgon2idProducesStableOutput
{
    uint8_t a[32], b[32], c[32];
    XCTAssertTrue(sfs_argon2id((const uint8_t *)"pw", 2, (const uint8_t *)"saltsalt", 8, 2, 16, 2, a, 32));
    XCTAssertTrue(sfs_argon2id((const uint8_t *)"pw", 2, (const uint8_t *)"saltsalt", 8, 2, 16, 2, b, 32));
    XCTAssertTrue(sfs_argon2id((const uint8_t *)"pW", 2, (const uint8_t *)"saltsalt", 8, 2, 16, 2, c, 32));
    XCTAssertEqual(memcmp(a, b, 32), 0);
    XCTAssertNotEqual(memcmp(a, c, 32), 0);
}

- (void)testBase32
{
    const uint8_t bytes[] = {0x00, 0xff, 0x10, 0x80, 0x7f, 0x01, 0x02};
    for (size_t len = 1; len <= sizeof(bytes); ++len) {
        char text[32];
        sfs_base32_encode(bytes, len, text);
        XCTAssertEqual(strlen(text), sfs_base32_encoded_len(len));
        uint8_t back[32];
        size_t back_len = 0;
        XCTAssertTrue(sfs_base32_decode(text, strlen(text), back, &back_len));
        XCTAssertEqual(back_len, len);
        XCTAssertEqual(memcmp(back, bytes, len), 0);
        // Decoding is case insensitive.
        for (char *p = text; *p; ++p) {
            *p = (char)tolower(*p);
        }
        XCTAssertTrue(sfs_base32_decode(text, strlen(text), back, &back_len));
        XCTAssertEqual(memcmp(back, bytes, len), 0);
    }
    char text[8];
    sfs_base32_encode((const uint8_t *)"\xff", 1, text);
    XCTAssertEqualObjects(@(text), @"96");  // 11111 111(00) -> alphabet[31], alphabet[28]
    uint8_t back[8];
    size_t back_len;
    // 'L' and 'O' are not part of the alphabet.
    XCTAssertFalse(sfs_base32_decode("AL", 2, back, &back_len));
    XCTAssertFalse(sfs_base32_decode("AO", 2, back, &back_len));
}

- (void)testBase64URL
{
    char text[64];
    sfs_base64url_encode((const uint8_t *)"\xfb\xff", 2, text);
    XCTAssertEqualObjects(@(text), @"-_8");
    uint8_t back[64];
    size_t len = 0;
    XCTAssertTrue(sfs_base64url_decode("-_8", 3, back, &len));
    XCTAssertEqual(len, 2u);
    XCTAssertTrue(sfs_base64url_decode("-_8=", 4, back, &len));
    XCTAssertEqual(len, 2u);
    XCTAssertFalse(sfs_base64url_decode("+/8", 3, back, &len));
    for (size_t n = 0; n < 20; ++n) {
        uint8_t in[20];
        sfs_random(in, n);
        sfs_base64url_encode(in, n, text);
        XCTAssertTrue(sfs_base64url_decode(text, strlen(text), back, &len));
        XCTAssertEqual(len, n);
        XCTAssertEqual(memcmp(in, back, n), 0);
    }
}

- (void)testHex
{
    uint8_t out[3];
    XCTAssertTrue(sfs_hex_decode("0aFf10", 6, out, 3));
    XCTAssertEqual(out[0], 0x0a);
    XCTAssertEqual(out[1], 0xff);
    XCTAssertEqual(out[2], 0x10);
    XCTAssertFalse(sfs_hex_decode("0g", 2, out, 1));
    XCTAssertFalse(sfs_hex_decode("0a1", 3, out, 1));
}

@end
