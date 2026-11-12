//
//  SFSReferenceRepositoryTests.m
//  securefsTests
//
//  Decrypts securefs' reference lite repositories with the core (names and
//  contents) and compares the result with the plain text tree, like securefs'
//  own regression test does through a mount.
//

#import "SFSTestSupport.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/sfs_names.h"
#include "core/sfs_stream.h"

@interface SFSReferenceRepositoryTests : XCTestCase
@end

@implementation SFSReferenceRepositoryTests {
    sfs_params _params;
    sfs_names _names;
    NSUInteger _files;
}

static NSString *nfc(NSString *s)
{
    return s.precomposedStringWithCanonicalMapping;
}

- (void)compareEncrypted:(NSString *)encDir withPlain:(NSString *)plainDir
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableSet<NSString *> *expected = [NSMutableSet set];
    for (NSString *name in [fm contentsOfDirectoryAtPath:plainDir error:NULL]) {
        [expected addObject:nfc(name)];
    }
    NSMutableSet<NSString *> *actual = [NSMutableSet set];
    for (NSString *underlying in [fm contentsOfDirectoryAtPath:encDir error:NULL]) {
        const char *u = underlying.fileSystemRepresentation;
        if (sfs_names_is_hidden_underlying(&_names, u, strlen(u))) {
            continue;
        }
        char plain[SFS_MAX_ENCRYPTED_COMPONENT];
        size_t len = 0;
        XCTAssertEqual(sfs_names_decrypt_component(&_names, u, strlen(u), plain, sizeof(plain), &len),
                       SFS_NAME_DECRYPTED, @"%@", underlying);
        NSString *name = nfc([[NSString alloc] initWithBytes:plain length:len encoding:NSUTF8StringEncoding]);
        [actual addObject:name];

        NSString *encPath = [encDir stringByAppendingPathComponent:underlying];
        NSString *plainPath = [plainDir stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        [fm fileExistsAtPath:encPath isDirectory:&isDir];
        if (isDir) {
            [self compareEncrypted:encPath withPlain:plainPath];
            continue;
        }
        int fd = open(encPath.fileSystemRepresentation, O_RDONLY);
        sfs_file *file = NULL;
        XCTAssertEqual(sfs_file_open(fd, &_params, true, false, &file), 0);
        uint64_t size = 0;
        XCTAssertEqual(sfs_file_size(file, &size), 0);
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)size];
        size_t got = 0;
        XCTAssertEqual(sfs_file_read(file, data.mutableBytes, 0, (size_t)size, &got), 0);
        XCTAssertEqualObjects(data, [NSData dataWithContentsOfFile:plainPath], @"%@", plainPath);

        // The size reported without opening the stream must agree.
        struct stat st;
        fstat(fd, &st);
        uint32_t padding = 0;
        XCTAssertEqual(sfs_read_padding(fd, &_params, &padding), 0);
        XCTAssertEqual(sfs_virtual_size_with_padding(&_params, (uint64_t)st.st_size, padding), size);
        sfs_file_close(file);
        close(fd);
        _files += 1;
    }
    XCTAssertEqualObjects(actual, expected, @"listing of %@", plainDir);
}

- (void)verifyRepository:(NSString *)repo config:(NSString *)config mode:(NSString *)mode
{
    NSString *dir = [SFSReferenceDirectory() stringByAppendingPathComponent:repo];
    XCTAssertEqual(SFSDecryptReferenceConfig([dir stringByAppendingPathComponent:config], mode, &_params), 0);
    sfs_names_init(&_names, &_params, false, true);
    _files = 0;
    [self compareEncrypted:dir withPlain:[SFSReferenceDirectory() stringByAppendingPathComponent:@"plain"]];
    XCTAssertEqual(_files, 5u);
}

- (void)testUnpaddedRepository
{
    [self verifyRepository:@"4" config:@".securefs.scrypt.PASSWORD.json" mode:@"PASSWORD"];
}

- (void)testPaddedRepository
{
    [self verifyRepository:@"4-padded" config:@".securefs.argon2id.PASSWORD_WITH_KEYFILE.json" mode:@"PASSWORD_WITH_KEYFILE"];
}

- (void)testPlainTextNamesRepository
{
    NSString *config = [[SFSReferenceDirectory() stringByAppendingPathComponent:@"4"]
        stringByAppendingPathComponent:@".securefs.argon2id.KEYFILE2.json"];
    XCTAssertEqual(SFSDecryptReferenceConfig(config, @"KEYFILE2", &_params), 0);
    sfs_names_init(&_names, &_params, true, false);
    _files = 0;
    [self compareEncrypted:[SFSReferenceDirectory() stringByAppendingPathComponent:@"4-plain-text-names"]
                 withPlain:[SFSReferenceDirectory() stringByAppendingPathComponent:@"plain"]];
    XCTAssertEqual(_files, 5u);
}

@end
