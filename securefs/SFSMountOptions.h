//
//  SFSMountOptions.h
//  securefs
//
//  Parses the options passed to the extension by `mount -F -t securefs -o ...` or by
//  FSClient's mountSingleVolume. Options are comma separated `key[=value]` pairs
//  after `-o`; values are percent-decoded so they can contain commas (`%2C`).
//
//    password=<text>      Repository password.
//    keyfile=<path>       Key file (must be readable by the sandboxed extension).
//    keydata=<base64>     Key file contents (used by the mounter app).
//    config=<path>        Config file; defaults to <data dir>/.securefs.json.
//    ro / rdonly          Read-only mount (also `--rdonly`).
//    insecure             Disable integrity verification.
//    noxattr              Disable extended attribute support.
//    plaintextnames       Repository was created with --plain-text-names.
//    normalization=none|nfc   Filename normalization (default nfc, as securefs on macOS).
//    uid=<n>, gid=<n>     Report every item as owned by this uid/gid.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SFSMountOptions : NSObject

+ (nullable instancetype)optionsWithTaskOptions:(NSArray<NSString *> *)taskOptions
                                          error:(NSError **)error;

/// Merges options given at a later stage (e.g. activation) into this instance.
- (BOOL)mergeTaskOptions:(NSArray<NSString *> *)taskOptions error:(NSError **)error;

@property (nonatomic, strong, nullable) NSData *password;
@property (nonatomic, copy, nullable) NSString *keyfilePath;
@property (nonatomic, strong, nullable) NSData *keyfileData;
@property (nonatomic, copy, nullable) NSString *configPath;
@property (nonatomic) BOOL readOnly;
@property (nonatomic) BOOL verify;
@property (nonatomic) BOOL xattr;
@property (nonatomic) BOOL plaintextNames;
@property (nonatomic) BOOL normalizeNFC;
@property (nonatomic) BOOL force;
@property (nonatomic) int64_t uidOverride;
@property (nonatomic) int64_t gidOverride;

/// Whether a password or key file was given.
@property (nonatomic, readonly) BOOL hasSecrets;

/// The options with secret values replaced, for logging.
+ (NSString *)redactedDescriptionOfTaskOptions:(NSArray<NSString *> *)taskOptions;

/// Wipes the secrets once the repository keys have been derived.
- (void)clearSecrets;

@end

NS_ASSUME_NONNULL_END
