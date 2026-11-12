//
//  SFSItem.h
//  securefs
//
//  A file system object of a mounted securefs volume. Each item corresponds to
//  one underlying (encrypted) file, directory or symlink, located by its parent
//  item and its encrypted name.
//

#import <FSKit/FSKit.h>
#include <pthread.h>

#include "core/sfs_stream.h"

NS_ASSUME_NONNULL_BEGIN

@class SFSDirectorySnapshot;

@interface SFSItem : FSItem

/// Creates the root item.
- (instancetype)initRootWithInode:(uint64_t)inode;

- (instancetype)initWithParent:(SFSItem *)parent
                 encryptedName:(NSData *)encryptedName
                     plainName:(FSFileName *)plainName
                          type:(FSItemType)type
                         inode:(uint64_t)inode;

@property (nonatomic, readonly, getter=isRoot) BOOL root;

/// The location of the item. Changed under the volume's namespace lock, and atomic
/// because a lookup may refresh them while other readers hold the lock shared.
@property (atomic, nullable) SFSItem *parent;
/// The underlying name as a NUL-terminated byte string ("." for the root).
@property (atomic, copy) NSData *encryptedName;
@property (atomic, copy) FSFileName *plainName;

@property (nonatomic, readonly) FSItemType type;
/// The underlying inode number, used as the item identifier.
@property (nonatomic, readonly) uint64_t inode;
/// The FSKit item identifier (FSItemIDRootDirectory for the root).
@property (nonatomic, readonly) FSItemID itemID;

/// Set once the item's last name has been removed.
@property (atomic) BOOL removed;

#pragma mark - Open file state (guarded by `lock`)

/// Serializes access to the open file state below.
@property (nonatomic, readonly) pthread_mutex_t *lock;
@property (nonatomic) int fd;
@property (nonatomic) BOOL fdWritable;
@property (nonatomic, nullable) sfs_file *file;
@property (nonatomic) FSVolumeOpenModes openModes;
/// Cached padding size of the file header (-1 when unknown).
@property (nonatomic) int64_t cachedPadding;

#pragma mark - Directory enumeration state (guarded by `lock`)

@property (nonatomic, nullable) SFSDirectorySnapshot *snapshot;

/// Releases the open file and descriptor. Requires `lock`.
- (void)closeFileLocked;

@end

/// A decrypted listing of a directory, reused across enumeration calls that share
/// the same verifier.
@interface SFSDirectoryEntry : NSObject
@property (nonatomic, copy) FSFileName *name;
@property (nonatomic, copy) NSData *encryptedName;
@property (nonatomic) FSItemType type;
@property (nonatomic) uint64_t inode;
@end

@interface SFSDirectorySnapshot : NSObject
@property (nonatomic, copy) NSArray<SFSDirectoryEntry *> *entries;
@property (nonatomic) FSDirectoryVerifier verifier;
@end

NS_ASSUME_NONNULL_END
