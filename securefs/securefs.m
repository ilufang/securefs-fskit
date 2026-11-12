//
//  securefs.m
//  securefs
//
//  Created by Fang Lu on 11/12/26.
//

#import "securefs.h"

#import "SFSLog.h"
#import "SFSMountOptions.h"
#import "SFSVolume.h"

#include <errno.h>
#include <sys/stat.h>

#include "core/sfs_config.h"
#include "core/sfs_crypto.h"

@implementation SecureFS {
    FSPathURLResource *_resource;
    BOOL _accessingResource;
    SFSVolume *_volume;
}

/// A stable container identifier for a data directory.
static FSContainerIdentifier *containerIdentifierForPath(NSString *path)
{
    struct stat st;
    uuid_t bytes = {0};
    if (stat(path.fileSystemRepresentation, &st) == 0) {
        memcpy(bytes, &st.st_dev, MIN(sizeof(st.st_dev), (size_t)8));
        memcpy(bytes + 8, &st.st_ino, MIN(sizeof(st.st_ino), (size_t)8));
    }
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:bytes];
    return [[FSContainerIdentifier alloc] initWithUUID:uuid];
}

- (void)probeResource:(FSResource *)resource
         replyHandler:(void (^)(FSProbeResult *_Nullable, NSError *_Nullable))replyHandler
{
    if (![resource isKindOfClass:[FSPathURLResource class]]) {
        replyHandler(FSProbeResult.notRecognizedProbeResult, nil);
        return;
    }
    NSURL *url = ((FSPathURLResource *)resource).url;
    BOOL accessing = [url startAccessingSecurityScopedResource];
    NSString *path = url.path;
    BOOL hasConfig = [[NSFileManager defaultManager]
        fileExistsAtPath:[path stringByAppendingPathComponent:@SFS_LEGACY_CONFIG_FILE_NAME]];
    FSContainerIdentifier *containerID = containerIdentifierForPath(path);
    if (accessing) {
        [url stopAccessingSecurityScopedResource];
    }
    // A config file elsewhere (-o config=...) is still allowed, so a missing one only
    // makes the directory "recognized" rather than unusable.
    NSString *name = path.lastPathComponent ?: @"securefs";
    replyHandler(hasConfig ? [FSProbeResult usableProbeResultWithName:name containerID:containerID]
                           : [FSProbeResult recognizedProbeResultWithName:name containerID:containerID],
                 nil);
}

- (void)loadResource:(FSResource *)resource
             options:(FSTaskOptions *)options
        replyHandler:(void (^)(FSVolume *_Nullable, NSError *_Nullable))reply
{
    if (![resource isKindOfClass:[FSPathURLResource class]]) {
        reply(nil, fs_errorForPOSIXError(EINVAL));
        return;
    }
    if (!sfs_crypto_init()) {
        SFSLogError("OpenSSL failed to initialize");
        reply(nil, fs_errorForPOSIXError(ENOTSUP));
        return;
    }
    SFSLogInfo("Load options: %{public}@", [SFSMountOptions redactedDescriptionOfTaskOptions:options.taskOptions]);
    NSError *error = nil;
    SFSMountOptions *mountOptions = [SFSMountOptions optionsWithTaskOptions:options.taskOptions error:&error];
    if (!mountOptions) {
        SFSLogError("Invalid mount options");
        reply(nil, error);
        return;
    }
    if (mountOptions.force) {
        // -f asks to format, which isn't supported.
        reply(nil, fs_errorForPOSIXError(ENOTSUP));
        return;
    }

    FSPathURLResource *pathResource = (FSPathURLResource *)resource;
    NSURL *url = pathResource.url;
    BOOL accessing = [url startAccessingSecurityScopedResource];
    if (!accessing) {
        SFSLogInfo("Resource URL is not security scoped; trying direct access");
    }
    // `mount -F` creates path resources that report isWritable == NO even for read-write
    // mounts, so only the explicit `ro`/`--rdonly` options make the volume read-only.
    SFSLogInfo("Resource writable: %d", pathResource.isWritable);
    NSString *dataDir = url.path;

    SFSVolume *volume = [[SFSVolume alloc] initWithRootPath:dataDir
                                                    options:mountOptions
                                                 volumeName:dataDir.lastPathComponent ?: @"securefs"
                                                      error:&error];
    int err = volume ? 0 : EIO;
    if (volume && mountOptions.hasSecrets) {
        // Secrets given at load time (e.g. by FSClient) are checked right away so a wrong
        // password fails the load. Otherwise the volume unlocks during activation, which is
        // where `mount -o ...` options are delivered.
        err = [volume unlock];
        if (err) {
            [volume shutdown];
            volume = nil;
        }
    }
    if (!volume) {
        if (accessing) {
            [url stopAccessingSecurityScopedResource];
        }
        reply(nil, error ?: fs_errorForPOSIXError(err));
        return;
    }
    _resource = pathResource;
    _accessingResource = accessing;
    _volume = volume;
    self.containerStatus = FSContainerStatus.ready;
    reply(volume, nil);
}

- (void)unloadResource:(FSResource *)resource
               options:(FSTaskOptions *)options
          replyHandler:(void (^)(NSError *_Nullable))reply
{
    [_volume shutdown];
    _volume = nil;
    if (_accessingResource) {
        [_resource.url stopAccessingSecurityScopedResource];
    }
    _accessingResource = NO;
    _resource = nil;
    self.containerStatus = [FSContainerStatus notReadyWithStatus:fs_errorForPOSIXError(ENODEV)];
    reply(nil);
}

@end
