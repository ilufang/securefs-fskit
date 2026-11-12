//
//  SFSUnlock.m
//  securefs
//

#import "SFSUnlock.h"

#import "SFSLog.h"
#import "SFSMountOptions.h"

#include <errno.h>

#include "core/sfs_config_json.h"
#include "core/sfs_crypto.h"

int SFSDecryptRepositoryParams(NSString *dataDir, SFSMountOptions *options, sfs_params *params)
{
    NSString *configPath = options.configPath
        ?: [dataDir stringByAppendingPathComponent:@SFS_LEGACY_CONFIG_FILE_NAME];
    NSError *readError = nil;
    NSData *json = [NSData dataWithContentsOfFile:configPath options:0 error:&readError];
    if (!json) {
        SFSLogError("Cannot read config %{public}@: %{public}@", configPath, readError);
        return ENOENT;
    }
    sfs_legacy_config config;
    if (sfs_legacy_config_parse_json(json.bytes, json.length, &config) != 0) {
        SFSLogError("Config %{public}@ is not a valid .securefs.json", configPath);
        return EINVAL;
    }

    NSData *keyfile = options.keyfileData;
    if (!keyfile && options.keyfilePath) {
        keyfile = [NSData dataWithContentsOfFile:options.keyfilePath options:0 error:&readError];
        if (!keyfile) {
            SFSLogError("Cannot read key file %{public}@: %{public}@", options.keyfilePath, readError);
            return EPERM;
        }
    }
    NSData *password = options.password;
    if (!password) {
        if (!keyfile) {
            SFSLogError("Neither a password nor a key file was given");
            return EAUTH;
        }
        password = [NSData dataWithBytes:SFS_KEYFILE_ONLY_PASSWORD length:strlen(SFS_KEYFILE_ONLY_PASSWORD)];
    }

    int err = sfs_legacy_config_decrypt(&config, password.bytes, password.length,
                                        keyfile ? keyfile.bytes : NULL, keyfile.length, params);
    sfs_secure_zero(&config, sizeof(config));
    switch (err) {
    case 0:
        return 0;
    case EACCES:
        SFSLogError("Wrong password or key file");
        return EAUTH;
    case ENOTSUP:
        SFSLogError("Unsupported repository (only the lite format, version 4, is supported)");
        return ENOTSUP;
    default:
        SFSLogError("Decrypting the config failed: %{darwin.errno}d", err);
        return err;
    }
}
