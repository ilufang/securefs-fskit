//
//  SFSMountOptionsTests.m
//  securefsTests
//

#import <XCTest/XCTest.h>

#import "SFSMountOptions.h"

@interface SFSMountOptionsTests : XCTestCase
@end

@implementation SFSMountOptionsTests

- (void)testDefaults
{
    SFSMountOptions *o = [SFSMountOptions optionsWithTaskOptions:@[] error:NULL];
    XCTAssertNotNil(o);
    XCTAssertNil(o.password);
    XCTAssertFalse(o.readOnly);
    XCTAssertTrue(o.verify);
    XCTAssertTrue(o.xattr);
    XCTAssertTrue(o.normalizeNFC);
    XCTAssertFalse(o.plaintextNames);
    XCTAssertEqual(o.uidOverride, -1);
    XCTAssertEqual(o.gidOverride, -1);
}

- (void)testMountCommandLineOptions
{
    NSError *error = nil;
    SFSMountOptions *o = [SFSMountOptions
        optionsWithTaskOptions:@[ @"-o", @"password=p%2Cw%3D%25,ro,nobrowse", @"-onoxattr,uid=501", @"-o", @"gid=20,insecure,normalization=none,plaintextnames,config=/tmp/c.json" ]
                         error:&error];
    XCTAssertNotNil(o, @"%@", error);
    XCTAssertEqualObjects([[NSString alloc] initWithData:o.password encoding:NSUTF8StringEncoding], @"p,w=%");
    XCTAssertTrue(o.readOnly);
    XCTAssertFalse(o.xattr);
    XCTAssertFalse(o.verify);
    XCTAssertFalse(o.normalizeNFC);
    XCTAssertTrue(o.plaintextNames);
    XCTAssertEqual(o.uidOverride, 501);
    XCTAssertEqual(o.gidOverride, 20);
    XCTAssertEqualObjects(o.configPath, @"/tmp/c.json");
}

- (void)testKeyData
{
    NSData *key = [NSData dataWithBytes:"\x01\x02\xff" length:3];
    NSString *b64 = [[key base64EncodedStringWithOptions:0]
        stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.alphanumericCharacterSet];
    SFSMountOptions *o = [SFSMountOptions optionsWithTaskOptions:@[ @"-o", [@"keydata=" stringByAppendingString:b64] ] error:NULL];
    XCTAssertEqualObjects(o.keyfileData, key);
    [o clearSecrets];
    XCTAssertNil(o.keyfileData);
}

- (void)testReadOnlyFlag
{
    XCTAssertTrue(([SFSMountOptions optionsWithTaskOptions:@[ @"--rdonly" ] error:NULL]).readOnly);
    XCTAssertTrue(([SFSMountOptions optionsWithTaskOptions:@[ @"-f" ] error:NULL]).force);
}

- (void)testInvalidOptions
{
    NSError *error = nil;
    XCTAssertNil(([SFSMountOptions optionsWithTaskOptions:@[ @"-o", @"uid=abc" ] error:&error]));
    XCTAssertNotNil(error);
    XCTAssertNil(([SFSMountOptions optionsWithTaskOptions:@[ @"-o", @"password" ] error:NULL]));
    XCTAssertNil(([SFSMountOptions optionsWithTaskOptions:@[ @"-o", @"normalization=casefold" ] error:NULL]));
    XCTAssertNil(([SFSMountOptions optionsWithTaskOptions:@[ @"-o", @"keydata=!!!" ] error:NULL]));
}

@end
