//
//  SFSStreamTests.m
//  securefsTests
//
//  The lite content stream: randomized comparison against an in-memory model,
//  integrity checks, sparse files and the on-disk layout.
//

#import "SFSTestSupport.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/sfs_stream.h"

@interface SFSStreamTests : XCTestCase
@end

@implementation SFSStreamTests {
    NSString *_dir;
}

- (void)setUp
{
    _dir = SFSMakeTemporaryDirectory(self);
}

- (int)openFile:(NSString *)name flags:(int)flags
{
    NSString *path = [_dir stringByAppendingPathComponent:name];
    return open(path.fileSystemRepresentation, flags | O_CLOEXEC, 0644);
}

/// Random writes, truncations and reads, checked against an NSMutableData model,
/// including reopening the file to make sure everything is persisted.
- (void)runModelTestWithParams:(sfs_params)params seed:(unsigned)seed
{
    srandom(seed);
    NSString *name = [NSString stringWithFormat:@"model-%u-%u-%u", params.block_size, params.iv_size, params.max_padding];
    int fd = [self openFile:name flags:O_RDWR | O_CREAT | O_TRUNC];
    XCTAssertGreaterThanOrEqual(fd, 0);
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, true, &file), 0);
    NSMutableData *model = [NSMutableData data];
    const uint64_t bs = params.block_size;

    for (int op = 0; op < 300; ++op) {
        long kind = random() % 10;
        if (kind < 6) {
            // Write, sometimes far past the end to create holes.
            uint64_t offset = (uint64_t)(random() % (long)(model.length + 3 * bs + 1));
            size_t len = (size_t)(random() % (long)(2 * bs + 7));
            NSMutableData *data = [NSMutableData dataWithLength:len];
            arc4random_buf(data.mutableBytes, len);
            XCTAssertEqual(sfs_file_write(file, data.bytes, offset, len), 0);
            if (len > 0) {
                if (offset + len > model.length) {
                    model.length = (NSUInteger)(offset + len);
                }
                [model replaceBytesInRange:NSMakeRange((NSUInteger)offset, len) withBytes:data.bytes];
            }
        } else if (kind < 8) {
            uint64_t size = (uint64_t)(random() % (long)(model.length + 2 * bs + 1));
            XCTAssertEqual(sfs_file_resize(file, size), 0);
            model.length = (NSUInteger)size;
        } else {
            uint64_t offset = (uint64_t)(random() % (long)(model.length + bs + 1));
            size_t len = (size_t)(random() % (long)(3 * bs + 1));
            NSMutableData *buf = [NSMutableData dataWithLength:len];
            size_t got = 0;
            XCTAssertEqual(sfs_file_read(file, buf.mutableBytes, offset, len, &got), 0);
            size_t expected = offset >= model.length ? 0 : MIN(len, (size_t)(model.length - offset));
            XCTAssertEqual(got, expected);
            if (expected) {
                XCTAssertEqual(memcmp(buf.bytes, (const uint8_t *)model.bytes + offset, expected), 0, @"op %d", op);
            }
        }
        uint64_t size = 0;
        XCTAssertEqual(sfs_file_size(file, &size), 0);
        XCTAssertEqual(size, model.length, @"op %d", op);
    }

    // The size computed from the physical size must agree with the stream.
    struct stat st;
    fstat(fd, &st);
    XCTAssertEqual(sfs_virtual_size_with_padding(&params, (uint64_t)st.st_size, sfs_file_padding(file)), model.length);
    uint32_t padding = 0;
    XCTAssertEqual(sfs_read_padding(fd, &params, &padding), 0);
    XCTAssertEqual(padding, sfs_file_padding(file));
    if (params.max_padding == 0) {
        XCTAssertEqual(sfs_virtual_size_from_physical(&params, (uint64_t)st.st_size), model.length);
    }
    sfs_file_close(file);
    close(fd);

    fd = [self openFile:name flags:O_RDONLY];
    XCTAssertEqual(sfs_file_open(fd, &params, true, false, &file), 0);
    NSMutableData *all = [NSMutableData dataWithLength:model.length + 10];
    size_t got = 0;
    XCTAssertEqual(sfs_file_read(file, all.mutableBytes, 0, all.length, &got), 0);
    XCTAssertEqual(got, model.length);
    all.length = got;
    XCTAssertEqualObjects(all, model);
    sfs_file_close(file);
    close(fd);
}

- (void)testRandomizedAgainstModel
{
    [self runModelTestWithParams:SFSTestParams(4096, 12, 0, 0) seed:1];
    [self runModelTestWithParams:SFSTestParams(4096, 32, 0, 0) seed:2];
    [self runModelTestWithParams:SFSTestParams(64, 12, 0, 0) seed:3];
    [self runModelTestWithParams:SFSTestParams(100, 16, 0, 0) seed:4];
}

- (void)testRandomizedWithPadding
{
    [self runModelTestWithParams:SFSTestParams(4096, 12, 256, 0) seed:5];
    [self runModelTestWithParams:SFSTestParams(64, 20, 1000, 0) seed:6];
}

- (void)testPhysicalLayout
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    int fd = [self openFile:@"layout" flags:O_RDWR | O_CREAT | O_TRUNC];
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, true, &file), 0);
    struct stat st;
    fstat(fd, &st);
    XCTAssertEqual(st.st_size, SFS_FILE_ID_SIZE);  // header written at creation

    uint8_t data[5000];
    arc4random_buf(data, sizeof(data));
    XCTAssertEqual(sfs_file_write(file, data, 0, sizeof(data)), 0);
    fstat(fd, &st);
    // id + (iv + 4096 + tag) + (iv + 904 + tag)
    XCTAssertEqual(st.st_size, 16 + (12 + 4096 + 16) + (12 + 904 + 16));
    sfs_file_close(file);
    close(fd);
}

- (void)testHolesAreSparseZeros
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    int fd = [self openFile:@"sparse" flags:O_RDWR | O_CREAT | O_TRUNC];
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, true, &file), 0);
    const uint64_t far = 10 * 4096 + 17;
    XCTAssertEqual(sfs_file_write(file, "end", far, 3), 0);
    uint64_t size = 0;
    sfs_file_size(file, &size);
    XCTAssertEqual(size, far + 3);
    // Blocks 1..9 were never written: their physical bytes are all zero.
    uint8_t raw[4124];
    ssize_t n = pread(fd, raw, sizeof(raw), 16 + 5 * 4124);
    XCTAssertEqual(n, (ssize_t)sizeof(raw));
    for (size_t i = 0; i < sizeof(raw); ++i) {
        if (raw[i]) {
            XCTFail(@"hole isn't zero");
            break;
        }
    }
    uint8_t buf[4096 * 10];
    size_t got = 0;
    XCTAssertEqual(sfs_file_read(file, buf, 0, sizeof(buf), &got), 0);
    XCTAssertEqual(got, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i) {
        if (buf[i]) {
            XCTFail(@"hole doesn't read as zeros");
            break;
        }
    }
    sfs_file_close(file);
    close(fd);
}

- (void)testTamperingIsDetected
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    int fd = [self openFile:@"tamper" flags:O_RDWR | O_CREAT | O_TRUNC];
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, true, &file), 0);
    uint8_t data[8192];
    arc4random_buf(data, sizeof(data));
    XCTAssertEqual(sfs_file_write(file, data, 0, sizeof(data)), 0);
    sfs_file_close(file);

    // Flip one ciphertext bit in the second block.
    uint8_t byte;
    off_t pos = 16 + 4124 + 12 + 100;
    pread(fd, &byte, 1, pos);
    byte ^= 0x04;
    pwrite(fd, &byte, 1, pos);

    uint8_t buf[8192];
    size_t got = 0;
    XCTAssertEqual(sfs_file_open(fd, &params, true, false, &file), 0);
    XCTAssertEqual(sfs_file_read(file, buf, 0, 4096, &got), 0);  // first block is intact
    XCTAssertEqual(sfs_file_read(file, buf, 4096, 4096, &got), EIO);
    sfs_file_close(file);

    // With verification disabled (mount option `insecure`), the data is returned anyway.
    XCTAssertEqual(sfs_file_open(fd, &params, false, false, &file), 0);
    XCTAssertEqual(sfs_file_read(file, buf, 0, sizeof(buf), &got), 0);
    XCTAssertEqual(got, sizeof(buf));
    sfs_file_close(file);

    // Blocks can't be swapped: the block number is authenticated.
    uint8_t b0[4124], b1[4124];
    pread(fd, b0, sizeof(b0), 16);
    pread(fd, b1, sizeof(b1), 16 + 4124);
    pwrite(fd, b0, sizeof(b0), 16 + 4124);
    XCTAssertEqual(sfs_file_open(fd, &params, true, false, &file), 0);
    XCTAssertEqual(sfs_file_read(file, buf, 4096, 4096, &got), EIO);
    sfs_file_close(file);
    close(fd);
}

- (void)testEmptyFileWithoutHeader
{
    // A zero-length underlying file (e.g. created by another tool) reads as empty and
    // gets a header on its first write, even through a read-only open.
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    int fd = [self openFile:@"empty" flags:O_RDWR | O_CREAT | O_TRUNC];
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, false, &file), 0);
    uint64_t size = 1;
    XCTAssertEqual(sfs_file_size(file, &size), 0);
    XCTAssertEqual(size, 0u);
    uint8_t buf[10];
    size_t got = 1;
    XCTAssertEqual(sfs_file_read(file, buf, 0, sizeof(buf), &got), 0);
    XCTAssertEqual(got, 0u);
    XCTAssertEqual(sfs_file_resize(file, 0), 0);
    struct stat st;
    fstat(fd, &st);
    XCTAssertEqual(st.st_size, 0);
    XCTAssertEqual(sfs_file_write(file, "hi", 0, 2), 0);
    XCTAssertEqual(sfs_file_size(file, &size), 0);
    XCTAssertEqual(size, 2u);
    sfs_file_close(file);
    close(fd);
}

- (void)testCorruptHeaderIsRejected
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    int fd = [self openFile:@"short" flags:O_RDWR | O_CREAT | O_TRUNC];
    write(fd, "short", 5);
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, false, &file), EIO);
    close(fd);
}

- (void)testReadOnlyDescriptorReportsWriteErrors
{
    sfs_params params = SFSTestParams(4096, 12, 0, 0);
    int fd = [self openFile:@"ro" flags:O_RDWR | O_CREAT | O_TRUNC];
    close(fd);
    fd = [self openFile:@"ro" flags:O_RDONLY];
    sfs_file *file = NULL;
    XCTAssertEqual(sfs_file_open(fd, &params, true, false, &file), 0);
    XCTAssertEqual(sfs_file_write(file, "x", 0, 1), EBADF);
    sfs_file_close(file);
    close(fd);
}

@end
