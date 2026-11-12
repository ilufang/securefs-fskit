//
//  SFSItem.m
//  securefs
//

#import "SFSItem.h"

#include <unistd.h>

@implementation SFSItem {
    pthread_mutex_t _lock;
}

- (instancetype)initRootWithInode:(uint64_t)inode
{
    self = [super init];
    if (self) {
        _root = YES;
        _encryptedName = [NSData dataWithBytes:"." length:2];
        _plainName = [FSFileName nameWithString:@"/"];
        _type = FSItemTypeDirectory;
        _inode = inode;
        [self commonInit];
    }
    return self;
}

- (instancetype)initWithParent:(SFSItem *)parent
                 encryptedName:(NSData *)encryptedName
                     plainName:(FSFileName *)plainName
                          type:(FSItemType)type
                         inode:(uint64_t)inode
{
    self = [super init];
    if (self) {
        _parent = parent;
        _encryptedName = [encryptedName copy];
        _plainName = [plainName copy];
        _type = type;
        _inode = inode;
        [self commonInit];
    }
    return self;
}

- (void)commonInit
{
    pthread_mutex_init(&_lock, NULL);
    _fd = -1;
    _cachedPadding = -1;
}

- (void)dealloc
{
    pthread_mutex_lock(&_lock);
    [self closeFileLocked];
    pthread_mutex_unlock(&_lock);
    pthread_mutex_destroy(&_lock);
}

- (pthread_mutex_t *)lock
{
    return &_lock;
}

- (FSItemID)itemID
{
    return _root ? FSItemIDRootDirectory : (FSItemID)_inode;
}

- (void)closeFileLocked
{
    if (_file) {
        sfs_file_close(_file);
        _file = NULL;
    }
    if (_fd >= 0) {
        close(_fd);
        _fd = -1;
    }
    _fdWritable = NO;
    _openModes = 0;
}

@end

@implementation SFSDirectoryEntry
@end

@implementation SFSDirectorySnapshot
@end
