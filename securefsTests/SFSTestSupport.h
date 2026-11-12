//
//  SFSTestSupport.h
//  securefsTests
//
//  Shared helpers: reference data from securefs' own regression suite, hex
//  conversion and temporary directories.
//

#import <XCTest/XCTest.h>

#include "core/sfs_config.h"

NS_ASSUME_NONNULL_BEGIN

/// Password of every reference repository.
extern NSString *const SFSReferencePassword;

/// .ref/securefs/test/reference
NSString *SFSReferenceDirectory(void);

NSData *SFSDataFromHex(NSString *hex);
NSString *SFSHexFromBytes(const void *bytes, size_t len);

/// Parses and decrypts a reference config. `mode` is the suffix of the config file name:
/// PASSWORD, KEYFILE, KEYFILE2, PASSWORD_WITH_KEYFILE or PASSWORD_WITH_KEYFILE2.
int SFSDecryptReferenceConfig(NSString *configPath, NSString *mode, sfs_params *out);

/// A fresh temporary directory, removed by the returned test case's teardown block.
NSString *SFSMakeTemporaryDirectory(XCTestCase *testCase);

/// Repository parameters with fixed keys for tests that don't need a real config.
sfs_params SFSTestParams(uint32_t blockSize, uint32_t ivSize, uint32_t maxPadding,
                         uint32_t longNameThreshold);

NS_ASSUME_NONNULL_END
