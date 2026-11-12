//
//  SFSVolume.h
//  securefs
//
//  The FSKit volume presenting a decrypted view of a securefs lite repository.
//

#import <FSKit/FSKit.h>

@class SFSMountOptions;

NS_ASSUME_NONNULL_BEGIN

@interface SFSVolume : FSVolume <FSVolumeHandler,
                                 FSVolumeOpenCloseHandler,
                                 FSVolumeReadWriteHandler,
                                 FSVolumeXattrHandler>

/// Opens the repository at `rootPath` (the data directory). The volume stays locked
/// until -unlock succeeds, which happens at the latest during activation, when the
/// options given at activation are merged into `options`.
- (nullable instancetype)initWithRootPath:(NSString *)rootPath
                                  options:(SFSMountOptions *)options
                               volumeName:(NSString *)volumeName
                                    error:(NSError **)error;

@property (nonatomic, readonly, getter=isUnlocked) BOOL unlocked;

/// Decrypts the repository config with the secrets in the options gathered so far,
/// then wipes them. Returns 0 or an errno value (EAUTH for missing/wrong secrets).
- (int)unlock;

/// Releases all items and the root descriptor. Call when the resource is unloaded.
- (void)shutdown;

@end

NS_ASSUME_NONNULL_END
