//
//  SFSUnlock.h
//  securefs
//
//  Reads and decrypts a repository's `.securefs.json` using the secrets given
//  in the mount options.
//

#import <Foundation/Foundation.h>

#include "core/sfs_config.h"

@class SFSMountOptions;

NS_ASSUME_NONNULL_BEGIN

/// Returns 0 or an errno value: ENOENT (config missing), EINVAL (malformed config),
/// EPERM (key file unreadable), EAUTH (missing or wrong secrets), ENOTSUP (not lite format).
int SFSDecryptRepositoryParams(NSString *dataDir, SFSMountOptions *options, sfs_params *params);

NS_ASSUME_NONNULL_END
