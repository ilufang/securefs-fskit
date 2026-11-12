//
//  SFSVolume.m
//  securefs
//
//  Every item is located by its parent directory and its encrypted name. Operations
//  open a descriptor for the parent directory and use the *at() family of system
//  calls, which keeps working when encrypted paths exceed PATH_MAX.
//
//  Locking:
//  - `_namespaceLock` (rwlock) protects item parent/name links. Operations that resolve
//    items take it for reading; rename takes it for writing.
//  - Each item's mutex protects its open file state and directory snapshot. It is
//    always acquired after the namespace lock, never before.
//  - `_itemsLock` protects the inode -> item cache.
//

#import "SFSVolume.h"

#import "SFSItem.h"
#import "SFSLog.h"
#import "SFSMountOptions.h"
#import "SFSUnlock.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <os/lock.h>
#include <stdatomic.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "core/sfs_crypto.h"
#include "core/sfs_longname.h"
#include "core/sfs_names.h"
#include "core/sfs_stream.h"
#include "core/sfs_xattr.h"

static NSError *posixError(int err)
{
    return fs_errorForPOSIXError(err ? err : EIO);
}

static FSItemType itemTypeForMode(mode_t mode)
{
    switch (mode & S_IFMT) {
    case S_IFDIR: return FSItemTypeDirectory;
    case S_IFREG: return FSItemTypeFile;
    case S_IFLNK: return FSItemTypeSymlink;
    case S_IFIFO: return FSItemTypeFIFO;
    case S_IFCHR: return FSItemTypeCharDevice;
    case S_IFBLK: return FSItemTypeBlockDevice;
    case S_IFSOCK: return FSItemTypeSocket;
    default: return FSItemTypeUnknown;
    }
}

/// Copies an FSFileName into a NUL-terminated buffer.
static BOOL fileNameToCString(FSFileName *name, char *out, size_t cap, size_t *out_len)
{
    NSData *data = name.data;
    if (data.length == 0 || data.length + 1 > cap || memchr(data.bytes, '\0', data.length)) {
        return NO;
    }
    memcpy(out, data.bytes, data.length);
    out[data.length] = '\0';
    *out_len = data.length;
    return YES;
}

static NSData *cStringData(const char *s)
{
    return [NSData dataWithBytes:s length:strlen(s) + 1];
}

static BOOL isASCII(const char *s, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if ((unsigned char)s[i] >= 0x80) {
            return NO;
        }
    }
    return YES;
}

/// The parent directory descriptor and name that locate an item.
typedef struct {
    int dirfd;
    BOOL closeDir;
    const char *name;
} SFSLocation;

static void releaseLocation(SFSLocation *loc)
{
    if (loc->closeDir && loc->dirfd >= 0) {
        close(loc->dirfd);
    }
    loc->dirfd = -1;
    loc->closeDir = NO;
}

@implementation SFSVolume {
    NSString *_rootPath;
    int _rootFD;
    sfs_params _params;
    sfs_names _names;
    /// The same translator without normalization, to find names stored un-normalized.
    sfs_names _rawNames;
    BOOL _readOnly;
    BOOL _verify;
    BOOL _xattr;
    int64_t _uidOverride;
    int64_t _gidOverride;
    SFSItem *_root;
    NSMutableDictionary<NSNumber *, SFSItem *> *_items;
    os_unfair_lock _itemsLock;
    pthread_rwlock_t _namespaceLock;
    _Atomic uint64_t _verifierCounter;
    FSVolumeSupportedCapabilities *_capabilities;
    /// Options accumulated from loading and activation; the secrets are wiped on unlock.
    SFSMountOptions *_options;
    BOOL _unlocked;
}

- (instancetype)initWithRootPath:(NSString *)rootPath
                         options:(SFSMountOptions *)options
                      volumeName:(NSString *)volumeName
                           error:(NSError **)error
{
    int fd = open(rootPath.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        int err = errno;
        SFSLogError("Cannot open data directory %{public}@: %{darwin.errno}d", rootPath, err);
        if (error) {
            *error = posixError(err);
        }
        return nil;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int err = errno;
        close(fd);
        if (error) {
            *error = posixError(err);
        }
        return nil;
    }

    // Derive a stable volume identifier from the data directory's identity.
    uuid_t bytes = {0};
    memcpy(bytes, &st.st_dev, MIN(sizeof(st.st_dev), (size_t)8));
    memcpy(bytes + 8, &st.st_ino, MIN(sizeof(st.st_ino), (size_t)8));
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:bytes];
    self = [super initWithVolumeID:[[FSVolumeIdentifier alloc] initWithUUID:uuid]
                        volumeName:[FSFileName nameWithString:volumeName]];
    if (!self) {
        close(fd);
        return nil;
    }
    _rootPath = [rootPath copy];
    _rootFD = fd;
    _options = options;
    _readOnly = options.readOnly;
    _root = [[SFSItem alloc] initRootWithInode:st.st_ino];
    _items = [NSMutableDictionary dictionary];
    _itemsLock = OS_UNFAIR_LOCK_INIT;
    pthread_rwlock_init(&_namespaceLock, NULL);
    _verifierCounter = 0;

    FSVolumeSupportedCapabilities *caps = [[FSVolumeSupportedCapabilities alloc] init];
    caps.supportsSymbolicLinks = YES;
    // Hard links would give one item several (parent, name) locations; not supported.
    caps.supportsHardLinks = NO;
    caps.supportsPersistentObjectIDs = YES;
    caps.supports64BitObjectIDs = YES;
    caps.supportsSparseFiles = YES;
    caps.supports2TBFiles = YES;
    caps.supportsHiddenFiles = YES;
    caps.supportsFastStatFS = YES;
    caps.caseFormat = FSVolumeCaseFormatSensitive;
    _capabilities = caps;
    return self;
}

- (BOOL)isUnlocked
{
    return _unlocked;
}

- (int)unlock
{
    if (_unlocked) {
        return 0;
    }
    sfs_params params;
    int err = SFSDecryptRepositoryParams(_rootPath, _options, &params);
    [_options clearSecrets];
    if (err) {
        return err;
    }
    SFSMountOptions *options = _options;
    _params = params;
    sfs_secure_zero(&params, sizeof(params));
    sfs_names_init(&_names, &_params, options.plaintextNames, options.normalizeNFC);
    sfs_names_init(&_rawNames, &_params, options.plaintextNames, false);
    _readOnly = options.readOnly;
    _verify = options.verify;
    _uidOverride = options.uidOverride;
    _gidOverride = options.gidOverride;
    // Only offer xattrs if the underlying file system supports them.
    _xattr = options.xattr && listxattr(_rootPath.fileSystemRepresentation, NULL, 0, 0) >= 0;
    _unlocked = YES;
    SFSLogInfo("Volume unlocked: block=%u iv=%u padding=%u longnames=%u plaintext=%d ro=%d xattr=%d",
               _params.block_size, _params.iv_size, _params.max_padding,
               _params.long_name_threshold, options.plaintextNames, _readOnly, _xattr);
    return 0;
}

- (void)dealloc
{
    [self shutdown];
    sfs_secure_zero(&_params, sizeof(_params));
    sfs_secure_zero(&_names, sizeof(_names));
    sfs_secure_zero(&_rawNames, sizeof(_rawNames));
    pthread_rwlock_destroy(&_namespaceLock);
}

- (void)shutdown
{
    os_unfair_lock_lock(&_itemsLock);
    NSArray<SFSItem *> *items = _items.allValues;
    [_items removeAllObjects];
    os_unfair_lock_unlock(&_itemsLock);
    for (SFSItem *item in items) {
        pthread_mutex_lock(item.lock);
        [item closeFileLocked];
        pthread_mutex_unlock(item.lock);
    }
    if (_rootFD >= 0) {
        close(_rootFD);
        _rootFD = -1;
    }
}

#pragma mark - Namespace helpers

- (void)lockNamespaceShared { pthread_rwlock_rdlock(&_namespaceLock); }
- (void)lockNamespaceExclusive { pthread_rwlock_wrlock(&_namespaceLock); }
- (void)unlockNamespace { pthread_rwlock_unlock(&_namespaceLock); }

/// Encrypted path components from the root to `item` (exclusive of the root).
- (NSArray<NSData *> *)componentsOfItem:(SFSItem *)item
{
    NSMutableArray<NSData *> *components = [NSMutableArray array];
    for (SFSItem *it = item; it && !it.isRoot; it = it.parent) {
        [components insertObject:it.encryptedName atIndex:0];
    }
    return components;
}

/// Opens a descriptor for directory `dir`. Requires the namespace lock.
- (int)openDirectory:(SFSItem *)dir fd:(int *)outFD
{
    if (dir.isRoot) {
        *outFD = dup(_rootFD);
        return *outFD < 0 ? errno : 0;
    }
    if (dir.removed) {
        return ENOENT;
    }
    NSArray<NSData *> *components = [self componentsOfItem:dir];
    NSMutableData *path = [NSMutableData data];
    for (NSData *c in components) {
        if (path.length) {
            [path appendBytes:"/" length:1];
        }
        [path appendBytes:c.bytes length:c.length - 1];
    }
    [path appendBytes:"" length:1];
    const int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    if (path.length < PATH_MAX) {
        int fd = openat(_rootFD, path.bytes, flags);
        if (fd < 0) {
            return errno;
        }
        *outFD = fd;
        return 0;
    }
    // Walk one component at a time when the relative path is too long.
    int fd = dup(_rootFD);
    for (NSData *c in components) {
        if (fd < 0) {
            return errno;
        }
        int next = openat(fd, c.bytes, flags);
        int err = errno;
        close(fd);
        if (next < 0) {
            return err;
        }
        fd = next;
    }
    *outFD = fd;
    return 0;
}

/// Locates `item` through its parent. Requires the namespace lock.
- (int)locateItem:(SFSItem *)item location:(SFSLocation *)loc
{
    loc->dirfd = -1;
    loc->closeDir = NO;
    loc->name = item.encryptedName.bytes;
    if (item.isRoot) {
        loc->dirfd = _rootFD;
        return 0;
    }
    if (item.removed || !item.parent) {
        return ENOENT;
    }
    int err = [self openDirectory:item.parent fd:&loc->dirfd];
    loc->closeDir = err == 0;
    return err;
}

/// Absolute path of `item` in the underlying file system. Requires the namespace lock.
- (NSString *)absolutePathOfItem:(SFSItem *)item
{
    NSMutableString *path = [_rootPath mutableCopy];
    for (NSData *c in [self componentsOfItem:item]) {
        [path appendString:@"/"];
        [path appendString:[NSString stringWithUTF8String:c.bytes] ?: @""];
    }
    return path;
}

- (NSString *)longNameTablePathForDirectory:(SFSItem *)dir
{
    return [[self absolutePathOfItem:dir]
        stringByAppendingPathComponent:@SFS_LONG_NAME_TABLE_FILE_NAME];
}

- (BOOL)isLongName:(const char *)encryptedName
{
    if (_names.plaintext || _names.long_name_threshold == 0) {
        return NO;
    }
    size_t len = strlen(encryptedName), slen = strlen(_names.long_name_suffix);
    return len > slen && strcmp(encryptedName + len - slen, _names.long_name_suffix) == 0;
}

#pragma mark - Item cache

- (SFSItem *)itemForStat:(const struct stat *)st
                  parent:(SFSItem *)parent
           encryptedName:(const char *)encryptedName
               plainName:(FSFileName *)plainName
{
    NSNumber *key = @(st->st_ino);
    os_unfair_lock_lock(&_itemsLock);
    SFSItem *item = _items[key];
    FSItemType type = itemTypeForMode(st->st_mode);
    if (item && (item.type != type || item.removed)) {
        // The inode number was reused for a different object.
        [_items removeObjectForKey:key];
        item = nil;
    }
    if (!item) {
        item = [[SFSItem alloc] initWithParent:parent
                                 encryptedName:cStringData(encryptedName)
                                     plainName:plainName
                                          type:type
                                         inode:st->st_ino];
        _items[key] = item;
    } else if (item.parent != parent || strcmp(item.encryptedName.bytes, encryptedName) != 0) {
        // Moved by someone else; follow the location it was found at. (Callers hold the
        // namespace lock for reading; these properties are only read under that lock and
        // the cache lock serializes concurrent updates.)
        item.parent = parent;
        item.encryptedName = cStringData(encryptedName);
        item.plainName = plainName;
    }
    os_unfair_lock_unlock(&_itemsLock);
    return item;
}

- (void)forgetItem:(SFSItem *)item
{
    if (item.isRoot) {
        return;
    }
    os_unfair_lock_lock(&_itemsLock);
    NSNumber *key = @(item.inode);
    if (_items[key] == item) {
        [_items removeObjectForKey:key];
    }
    os_unfair_lock_unlock(&_itemsLock);
}

- (void)invalidateSnapshotOfDirectory:(SFSItem *)dir
{
    pthread_mutex_lock(dir.lock);
    dir.snapshot = nil;
    pthread_mutex_unlock(dir.lock);
}

#pragma mark - Attributes

/// Plaintext size of a regular file given its physical size.
- (uint64_t)virtualSizeOfFile:(SFSItem *)item stat:(const struct stat *)st location:(SFSLocation *)loc
{
    if (_params.max_padding == 0) {
        return sfs_virtual_size_from_physical(&_params, (uint64_t)st->st_size);
    }
    // With padding, the header has to be read to learn the padding size.
    int64_t padding = item ? item.cachedPadding : -1;
    if (padding < 0) {
        uint32_t pad = 0;
        int fd = loc ? openat(loc->dirfd, loc->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
        if (fd >= 0) {
            if (sfs_read_padding(fd, &_params, &pad) == 0) {
                padding = pad;
                if (item && st->st_size >= SFS_FILE_ID_SIZE) {
                    item.cachedPadding = pad;
                }
            }
            close(fd);
        }
        if (padding < 0) {
            padding = 0;
        }
    }
    return sfs_virtual_size_with_padding(&_params, (uint64_t)st->st_size, (uint32_t)padding);
}

/// Length of a symlink's decrypted target.
- (uint64_t)symlinkSizeAtLocation:(SFSLocation *)loc fallback:(uint64_t)fallback
{
    if (!loc) {
        return fallback;
    }
    char buf[PATH_MAX * 4];
    ssize_t n = readlinkat(loc->dirfd, loc->name, buf, sizeof(buf));
    if (n <= 0) {
        return fallback;
    }
    char *plain = NULL;
    size_t plain_len = 0;
    if (sfs_names_decrypt_symlink(&_names, buf, (size_t)n, &plain, &plain_len) != 0) {
        return fallback;
    }
    free(plain);
    return plain_len;
}

- (FSItemAttributes *)attributesForStat:(const struct stat *)st
                                   item:(nullable SFSItem *)item
                                 itemID:(FSItemID)itemID
                               parentID:(FSItemID)parentID
                               location:(nullable SFSLocation *)loc
{
    FSItemAttributes *attrs = [[FSItemAttributes alloc] init];
    FSItemType type = itemTypeForMode(st->st_mode);
    attrs.type = type;
    attrs.mode = st->st_mode & 07777;
    attrs.linkCount = st->st_nlink;
    attrs.uid = _uidOverride >= 0 ? (uint32_t)_uidOverride : st->st_uid;
    attrs.gid = _gidOverride >= 0 ? (uint32_t)_gidOverride : st->st_gid;
    attrs.flags = st->st_flags;
    switch (type) {
    case FSItemTypeFile:
        attrs.size = [self virtualSizeOfFile:item stat:st location:loc];
        break;
    case FSItemTypeSymlink:
        attrs.size = [self symlinkSizeAtLocation:loc fallback:(uint64_t)st->st_size];
        break;
    default:
        attrs.size = (uint64_t)st->st_size;
        break;
    }
    attrs.allocSize = (uint64_t)st->st_blocks * 512;
    attrs.fileID = itemID;
    attrs.parentID = parentID;
    attrs.accessTime = st->st_atimespec;
    attrs.modifyTime = st->st_mtimespec;
    attrs.changeTime = st->st_ctimespec;
    attrs.birthTime = st->st_birthtimespec;
    attrs.backupTime = (struct timespec){0, 0};
    attrs.addedTime = st->st_birthtimespec;
    if (loc) {
        // The date added is only available through getattrlist.
        struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_ADDEDTIME};
        struct {
            uint32_t length;
            struct timespec added;
        } __attribute__((aligned(4), packed)) buf;
        if (getattrlistat(loc->dirfd, loc->name, &al, &buf, sizeof(buf), FSOPT_NOFOLLOW) == 0
            && buf.length >= sizeof(buf)) {
            attrs.addedTime = buf.added;
        }
    }
    return attrs;
}

- (FSItemID)parentIDOfItem:(SFSItem *)item
{
    if (item.isRoot) {
        return FSItemIDParentOfRoot;
    }
    return item.parent ? item.parent.itemID : FSItemIDInvalid;
}

/// Current attributes of `item`. Requires the namespace lock.
- (FSItemAttributes *)attributesOfItem:(SFSItem *)item error:(int *)outErr
{
    struct stat st;
    SFSLocation loc;
    int err = [self locateItem:item location:&loc];
    if (err == 0) {
        if (fstatat(loc.dirfd, loc.name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            err = errno;
        }
    }
    if (err == ENOENT && item.removed) {
        // An unlinked but still open file remains reachable through its descriptor.
        pthread_mutex_lock(item.lock);
        int fd = item.fd;
        err = fd >= 0 && fstat(fd, &st) == 0 ? 0 : ENOENT;
        pthread_mutex_unlock(item.lock);
        if (err == 0) {
            releaseLocation(&loc);
            return [self attributesForStat:&st
                                      item:item
                                    itemID:item.itemID
                                  parentID:[self parentIDOfItem:item]
                                  location:NULL];
        }
    }
    if (err) {
        releaseLocation(&loc);
        *outErr = err;
        return nil;
    }
    FSItemAttributes *attrs = [self attributesForStat:&st
                                                 item:item
                                               itemID:item.itemID
                                             parentID:[self parentIDOfItem:item]
                                             location:&loc];
    releaseLocation(&loc);
    return attrs;
}

#pragma mark - Name resolution

/// Finds the underlying entry for `name` in directory `dirfd`.
///
/// Names are encrypted after NFC normalization. Repositories written elsewhere may
/// store un-normalized names, so fall back to the raw bytes, and for non-ASCII names
/// finally to a normalization-insensitive scan of the directory.
- (int)resolveName:(FSFileName *)name
       inDirectory:(SFSItem *)dir
             dirFD:(int)dirfd
     encryptedName:(char *)enc
              stat:(struct stat *)st
        storedName:(FSFileName *__autoreleasing *)stored
{
    char plain[SFS_MAX_ENCRYPTED_COMPONENT];
    size_t plain_len = 0;
    bool is_long = false;
    if (!fileNameToCString(name, plain, sizeof(plain), &plain_len)) {
        return EINVAL;
    }
    int err = sfs_names_encrypt_component(&_names, plain, plain_len, enc,
                                          SFS_MAX_ENCRYPTED_COMPONENT, NULL, 0, &is_long);
    if (err) {
        return err;
    }
    if (fstatat(dirfd, enc, st, AT_SYMLINK_NOFOLLOW) == 0) {
        NSString *s = name.string;
        *stored = _names.normalize_nfc && s
            ? [FSFileName nameWithString:s.precomposedStringWithCanonicalMapping]
            : name;
        return 0;
    }
    if (errno != ENOENT) {
        return errno;
    }
    if (_names.plaintext || isASCII(plain, plain_len)) {
        return ENOENT;
    }
    if (_names.normalize_nfc
        && sfs_names_encrypt_component(&_rawNames, plain, plain_len, enc,
                                       SFS_MAX_ENCRYPTED_COMPONENT, NULL, 0, &is_long)
            == 0
        && fstatat(dirfd, enc, st, AT_SYMLINK_NOFOLLOW) == 0) {
        *stored = name;
        return 0;
    }
    NSString *wanted = name.string.precomposedStringWithCanonicalMapping;
    if (!wanted) {
        return ENOENT;
    }
    __block int result = ENOENT;
    [self forEachEntryInDirectory:dir
                            dirFD:dirfd
                            block:^BOOL(const char *underlying, FSFileName *decrypted, uint8_t dtype) {
        NSString *candidate = decrypted.string;
        if (candidate && [candidate.precomposedStringWithCanonicalMapping isEqualToString:wanted]) {
            strlcpy(enc, underlying, SFS_MAX_ENCRYPTED_COMPONENT);
            result = fstatat(dirfd, enc, st, AT_SYMLINK_NOFOLLOW) == 0 ? 0 : errno;
            *stored = decrypted;
            return NO;
        }
        return YES;
    }];
    return result;
}

/// Calls `block` with each visible entry of a directory until it returns NO.
- (int)forEachEntryInDirectory:(SFSItem *)dir
                         dirFD:(int)dirfd
                         block:(BOOL (^)(const char *underlying, FSFileName *name,
                                         uint8_t dtype))block
{
    int fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return errno;
    }
    DIR *dp = fdopendir(fd);
    if (!dp) {
        int err = errno;
        close(fd);
        return err;
    }
    NSString *tablePath = nil;
    char plain[SFS_MAX_ENCRYPTED_COMPONENT];
    char full[SFS_MAX_ENCRYPTED_COMPONENT];
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        size_t len = de->d_namlen;
        if (sfs_names_is_hidden_underlying(&_names, de->d_name, len)) {
            continue;
        }
        size_t plain_len = 0;
        sfs_name_kind kind =
            sfs_names_decrypt_component(&_names, de->d_name, len, plain, sizeof(plain), &plain_len);
        if (kind == SFS_NAME_LONG) {
            if (!tablePath) {
                tablePath = [self longNameTablePathForDirectory:dir];
            }
            if (sfs_longname_lookup(tablePath.fileSystemRepresentation, de->d_name, full,
                                    sizeof(full))
                    != 0
                || sfs_names_decrypt_component(&_names, full, strlen(full), plain, sizeof(plain),
                                               &plain_len)
                    != SFS_NAME_DECRYPTED) {
                SFSLogError("Missing long name mapping for an entry; skipping it");
                continue;
            }
        } else if (kind != SFS_NAME_DECRYPTED) {
            continue;
        }
        FSFileName *name = [FSFileName nameWithBytes:plain length:plain_len];
        BOOL keepGoing;
        @autoreleasepool {
            keepGoing = block(de->d_name, name, de->d_type);
        }
        if (!keepGoing) {
            break;
        }
    }
    closedir(dp);
    return 0;
}

/// Encrypts a new name for creation. `longFull` receives the table entry for long names.
- (int)encryptNewName:(FSFileName *)name
        encryptedName:(char *)enc
             longFull:(char *)longFull
               isLong:(bool *)isLong
{
    char plain[SFS_MAX_ENCRYPTED_COMPONENT];
    size_t plain_len = 0;
    if (!fileNameToCString(name, plain, sizeof(plain), &plain_len)) {
        return EINVAL;
    }
    if ((plain_len == 1 && plain[0] == '.') || (plain_len == 2 && plain[0] == '.' && plain[1] == '.')) {
        return EINVAL;
    }
    if (_names.plaintext && sfs_names_is_hidden_underlying(&_names, plain, plain_len)) {
        // Don't let a plain text repository's internal files be shadowed.
        return EPERM;
    }
    return sfs_names_encrypt_component(&_names, plain, plain_len, enc, SFS_MAX_ENCRYPTED_COMPONENT,
                                       longFull, SFS_MAX_ENCRYPTED_COMPONENT, isLong);
}

#pragma mark - FSVolumeCommonOperations / PathConf

- (FSVolumeSupportedCapabilities *)supportedVolumeCapabilities
{
    return _capabilities;
}

- (FSStatFSResult *)volumeStatistics
{
    FSStatFSResult *result = [[FSStatFSResult alloc] initWithFileSystemTypeName:@"securefs"];
    struct statfs sfs;
    if (_rootFD >= 0 && fstatfs(_rootFD, &sfs) == 0) {
        result.blockSize = sfs.f_bsize;
        result.ioSize = sfs.f_iosize;
        result.totalBlocks = sfs.f_blocks;
        result.availableBlocks = sfs.f_bavail;
        result.freeBlocks = sfs.f_bfree;
        result.usedBlocks = sfs.f_blocks - sfs.f_bfree;
        result.totalBytes = sfs.f_blocks * sfs.f_bsize;
        result.availableBytes = sfs.f_bavail * sfs.f_bsize;
        result.freeBytes = sfs.f_bfree * sfs.f_bsize;
        result.usedBytes = (sfs.f_blocks - sfs.f_bfree) * sfs.f_bsize;
        result.totalFiles = sfs.f_files;
        result.freeFiles = sfs.f_ffree;
    }
    return result;
}

- (FSMountOptions)requestedMountOptions
{
    return _readOnly ? FSMountOptionsReadOnly : 0;
}

- (NSInteger)maximumLinkCount
{
    long v = _rootFD >= 0 ? fpathconf(_rootFD, _PC_LINK_MAX) : -1;
    return v > 0 ? v : 1;
}

- (NSInteger)maximumNameLength
{
    long physical = _rootFD >= 0 ? fpathconf(_rootFD, _PC_NAME_MAX) : 255;
    if (physical <= 0) {
        physical = 255;
    }
    uint32_t virtual = sfs_names_max_component_length(&_names, (uint32_t)physical);
    return MIN((NSInteger)virtual, (NSInteger)NAME_MAX);
}

- (BOOL)restrictsOwnershipChanges
{
    return YES;
}

- (BOOL)truncatesLongNames
{
    return NO;
}

- (NSInteger)maximumFileSizeInBits
{
    // Files are limited to 2^31 - 1 blocks.
    uint64_t max = ((1ULL << 31) - 1) * _params.block_size;
    return 64 - __builtin_clzll(max) + 1;
}

- (void)mountWithOptions:(FSTaskOptions *)options replyHandler:(void (^)(NSError *))reply
{
    reply(nil);
}

- (void)unmountWithReplyHandler:(void (^)(void))reply
{
    reply();
}

- (void)synchronizeWithFlags:(FSSyncFlags)flags replyHandler:(void (^)(NSError *))reply
{
    os_unfair_lock_lock(&_itemsLock);
    NSArray<SFSItem *> *items = _items.allValues;
    os_unfair_lock_unlock(&_itemsLock);
    for (SFSItem *item in items) {
        pthread_mutex_lock(item.lock);
        if (item.fd >= 0 && item.fdWritable) {
            if (flags == FSSyncFlagsWait) {
                fcntl(item.fd, F_FULLFSYNC);
            } else {
                fsync(item.fd);
            }
        }
        pthread_mutex_unlock(item.lock);
    }
    reply(nil);
}

- (void)reclaimItem:(FSItem *)fsItem replyHandler:(void (^)(NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    [self forgetItem:item];
    pthread_mutex_lock(item.lock);
    [item closeFileLocked];
    item.snapshot = nil;
    pthread_mutex_unlock(item.lock);
    reply(nil);
}

#pragma mark - FSVolumeHandler

- (void)activateVolumeWithOptions:(FSTaskOptions *)options
                     replyHandler:(void (^)(FSActivateResult *, NSError *))reply
{
    // Options declared in FSActivateOptionSyntax (such as `-o password=...`) arrive here
    // rather than at load time.
    SFSLogInfo("Activate options: %{public}@", [SFSMountOptions redactedDescriptionOfTaskOptions:options.taskOptions]);
    NSError *error = nil;
    if (![_options mergeTaskOptions:options.taskOptions error:&error]) {
        SFSLogError("Invalid activation options");
        reply(nil, error);
        return;
    }
    if (!_unlocked) {
        int err = [self unlock];
        if (err) {
            reply(nil, posixError(err));
            return;
        }
    } else {
        // Already unlocked at load time; only a read-only request can still apply.
        [_options clearSecrets];
        _readOnly = _readOnly || _options.readOnly;
    }
    FSActivateResult *result = [[FSActivateResult alloc] initWithRootItem:_root];
    reply(result, result ? nil : posixError(EIO));
}

- (void)deactivateVolumeWithOptions:(FSDeactivateOptions)options
                       replyHandler:(void (^)(NSError *))reply
{
    os_unfair_lock_lock(&_itemsLock);
    NSArray<SFSItem *> *items = _items.allValues;
    [_items removeAllObjects];
    os_unfair_lock_unlock(&_itemsLock);
    for (SFSItem *item in items) {
        pthread_mutex_lock(item.lock);
        [item closeFileLocked];
        pthread_mutex_unlock(item.lock);
    }
    reply(nil);
}

- (void)lookupItemNamed:(FSFileName *)name
            inDirectory:(FSItem *)directory
                context:(FSContext *)context
           replyHandler:(void (^)(FSLookupItemResult *, NSError *))reply
{
    SFSItem *dir = (SFSItem *)directory;
    [self lockNamespaceShared];
    int dirfd = -1;
    int err = [self openDirectory:dir fd:&dirfd];
    FSLookupItemResult *result = nil;
    if (err == 0) {
        char enc[SFS_MAX_ENCRYPTED_COMPONENT];
        struct stat st;
        FSFileName *stored = nil;
        err = [self resolveName:name inDirectory:dir dirFD:dirfd encryptedName:enc stat:&st storedName:&stored];
        if (err == 0) {
            SFSItem *item = [self itemForStat:&st parent:dir encryptedName:enc plainName:stored];
            SFSLocation loc = {.dirfd = dirfd, .closeDir = NO, .name = enc};
            FSItemAttributes *attrs = [self attributesForStat:&st
                                                         item:item
                                                       itemID:item.itemID
                                                     parentID:dir.itemID
                                                     location:&loc];
            result = [[FSLookupItemResult alloc] initWithFoundItem:item itemName:stored itemAttributes:attrs];
        }
        close(dirfd);
    }
    [self unlockNamespace];
    reply(result, result ? nil : posixError(err));
}

- (void)getAttributes:(FSItemGetAttributesRequest *)desiredAttributes
               ofItem:(FSItem *)fsItem
              context:(FSContext *)context
         replyHandler:(void (^)(FSGetAttributesResult *, NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    int err = 0;
    [self lockNamespaceShared];
    FSItemAttributes *attrs = [self attributesOfItem:item error:&err];
    [self unlockNamespace];
    FSGetAttributesResult *result = attrs ? [[FSGetAttributesResult alloc] initWithAttributes:attrs] : nil;
    reply(result, result ? nil : posixError(err));
}

/// Truncates or extends a regular file. Requires the namespace lock.
- (int)resizeItem:(SFSItem *)item location:(SFSLocation *)loc size:(uint64_t)size
{
    pthread_mutex_lock(item.lock);
    int err;
    if (item.file && item.fdWritable) {
        err = sfs_file_resize(item.file, size);
    } else {
        int fd = openat(loc->dirfd, loc->name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            err = errno;
        } else {
            sfs_file *file = NULL;
            err = sfs_file_open(fd, &_params, _verify, false, &file);
            if (err == 0) {
                err = sfs_file_resize(file, size);
                if (err == 0 && file) {
                    item.cachedPadding = sfs_file_padding(file);
                }
                sfs_file_close(file);
            }
            close(fd);
        }
    }
    pthread_mutex_unlock(item.lock);
    return err;
}

/// Applies the settable attributes in `request` and marks them consumed.
/// Requires the namespace lock.
- (int)applyAttributes:(FSItemSetAttributesRequest *)request
                toItem:(SFSItem *)item
              location:(SFSLocation *)loc
              creating:(BOOL)creating
{
    FSItemAttribute consumed = 0;
    int err = 0;
    if ([request isValid:FSItemAttributeSize]) {
        if (item.type != FSItemTypeFile) {
            return item.type == FSItemTypeDirectory ? EISDIR : EINVAL;
        }
        err = [self resizeItem:item location:loc size:request.size];
        if (err) {
            return err;
        }
        consumed |= FSItemAttributeSize;
    }
    if ([request isValid:FSItemAttributeMode]) {
        if (fchmodat(loc->dirfd, loc->name, request.mode & 07777, AT_SYMLINK_NOFOLLOW) != 0) {
            // Symlink permissions can't always be changed; that's not worth failing for.
            if (!(item.type == FSItemTypeSymlink && (errno == ENOTSUP || errno == EOPNOTSUPP))) {
                return errno;
            }
        }
        consumed |= FSItemAttributeMode;
    }
    if ([request isValid:FSItemAttributeUID] || [request isValid:FSItemAttributeGID]) {
        uid_t uid = [request isValid:FSItemAttributeUID] ? request.uid : (uid_t)-1;
        gid_t gid = [request isValid:FSItemAttributeGID] ? request.gid : (gid_t)-1;
        if (_uidOverride >= 0 && uid == (uid_t)_uidOverride) {
            uid = (uid_t)-1;
        }
        if (_gidOverride >= 0 && gid == (gid_t)_gidOverride) {
            gid = (gid_t)-1;
        }
        // Skip no-op changes: an unprivileged extension can't chown at all, and FSKit sends
        // the creator's ownership along with every new item.
        struct stat st;
        if (fstatat(loc->dirfd, loc->name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (uid == st.st_uid) {
                uid = (uid_t)-1;
            }
            if (gid == st.st_gid) {
                gid = (gid_t)-1;
            }
        }
        if ((uid != (uid_t)-1 || gid != (gid_t)-1)
            && fchownat(loc->dirfd, loc->name, uid, gid, AT_SYMLINK_NOFOLLOW) != 0) {
            if (!(creating && errno == EPERM)) {
                SFSLogError("chown to %d:%d failed: %{darwin.errno}d", (int)uid, (int)gid, errno);
                return errno;
            }
            // New items keep the owner the underlying file system assigned (as with securefs).
            SFSLogDebug("Ignoring ownership %d:%d for a new item", (int)uid, (int)gid);
        }
        consumed |= [request isValid:FSItemAttributeUID] ? FSItemAttributeUID : 0;
        consumed |= [request isValid:FSItemAttributeGID] ? FSItemAttributeGID : 0;
    }
    if ([request isValid:FSItemAttributeAccessTime] || [request isValid:FSItemAttributeModifyTime]) {
        struct timespec times[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
        if ([request isValid:FSItemAttributeAccessTime]) {
            times[0] = request.accessTime;
            consumed |= FSItemAttributeAccessTime;
        }
        if ([request isValid:FSItemAttributeModifyTime]) {
            times[1] = request.modifyTime;
            consumed |= FSItemAttributeModifyTime;
        }
        if (utimensat(loc->dirfd, loc->name, times, AT_SYMLINK_NOFOLLOW) != 0) {
            SFSLogError("Setting times failed: %{darwin.errno}d", errno);
            return errno;
        }
    }
    if ([request isValid:FSItemAttributeBirthTime] || [request isValid:FSItemAttributeFlags]
        || [request isValid:FSItemAttributeBackupTime]) {
        // These are only settable through setattrlist.
        struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT};
        uint8_t buf[64];
        size_t len = 0;
        if ([request isValid:FSItemAttributeBirthTime]) {
            al.commonattr |= ATTR_CMN_CRTIME;
            struct timespec t = request.birthTime;
            memcpy(buf + len, &t, sizeof(t));
            len += sizeof(t);
            consumed |= FSItemAttributeBirthTime;
        }
        if ([request isValid:FSItemAttributeBackupTime]) {
            al.commonattr |= ATTR_CMN_BKUPTIME;
            struct timespec t = request.backupTime;
            memcpy(buf + len, &t, sizeof(t));
            len += sizeof(t);
            consumed |= FSItemAttributeBackupTime;
        }
        if ([request isValid:FSItemAttributeFlags]) {
            al.commonattr |= ATTR_CMN_FLAGS;
            uint32_t flags = request.flags;
            memcpy(buf + len, &flags, sizeof(flags));
            len += sizeof(flags);
            consumed |= FSItemAttributeFlags;
        }
        if (setattrlistat(loc->dirfd, loc->name, &al, buf, len, FSOPT_NOFOLLOW) != 0) {
            SFSLogError("setattrlist (0x%x) failed: %{darwin.errno}d", al.commonattr, errno);
            return errno;
        }
    }
    request.consumedAttributes |= consumed;
    return 0;
}

- (void)setAttributes:(FSItemSetAttributesRequest *)newAttributes
               onItem:(FSItem *)fsItem
              context:(FSContext *)context
         replyHandler:(void (^)(FSSetAttributesResult *, NSError *))reply
{
    if (_readOnly) {
        reply(nil, posixError(EROFS));
        return;
    }
    SFSItem *item = (SFSItem *)fsItem;
    [self lockNamespaceShared];
    SFSLocation loc;
    int err = [self locateItem:item location:&loc];
    FSItemAttributes *attrs = nil;
    if (err == 0) {
        err = [self applyAttributes:newAttributes toItem:item location:&loc creating:NO];
    }
    releaseLocation(&loc);
    if (err == 0) {
        attrs = [self attributesOfItem:item error:&err];
    }
    [self unlockNamespace];
    FSSetAttributesResult *result =
        attrs ? [[FSSetAttributesResult alloc] initWithAttributes:attrs freeSpace:nil] : nil;
    reply(result, result ? nil : posixError(err));
}

/// Shared implementation of item and symlink creation.
- (void)createItemNamed:(FSFileName *)name
                   type:(FSItemType)type
            inDirectory:(SFSItem *)dir
             attributes:(FSItemSetAttributesRequest *)attributes
           linkContents:(nullable FSFileName *)contents
             completion:(void (^)(SFSItem *item, FSItemAttributes *attrs,
                                  FSItemAttributes *dirAttrs, int err))completion
{
    if (_readOnly) {
        completion(nil, nil, nil, EROFS);
        return;
    }
    char enc[SFS_MAX_ENCRYPTED_COMPONENT], longFull[SFS_MAX_ENCRYPTED_COMPONENT];
    bool isLong = false;
    int err = [self encryptNewName:name encryptedName:enc longFull:longFull isLong:&isLong];
    if (err) {
        completion(nil, nil, nil, err);
        return;
    }
    char *linkTarget = NULL;
    size_t linkLen = 0;
    if (type == FSItemTypeSymlink) {
        NSData *data = contents.data;
        if (data.length == 0) {
            completion(nil, nil, nil, EINVAL);
            return;
        }
        err = sfs_names_encrypt_symlink(&_names, data.bytes, data.length, &linkTarget, &linkLen);
        if (err) {
            completion(nil, nil, nil, err);
            return;
        }
    } else if (type != FSItemTypeFile && type != FSItemTypeDirectory) {
        completion(nil, nil, nil, ENOTSUP);
        return;
    }

    mode_t mode = [attributes isValid:FSItemAttributeMode] ? (attributes.mode & 07777)
                                                           : (type == FSItemTypeDirectory ? 0755 : 0644);
    if (type == FSItemTypeFile) {
        // The header must stay readable for the key to be derived.
        mode |= S_IRUSR;
    }

    [self lockNamespaceShared];
    int dirfd = -1;
    SFSItem *item = nil;
    FSItemAttributes *attrs = nil, *dirAttrs = nil;
    sfs_longname_txn *txn = NULL;
    err = [self openDirectory:dir fd:&dirfd];
    if (err == 0 && isLong) {
        NSString *table = [self longNameTablePathForDirectory:dir];
        err = sfs_longname_begin(table.fileSystemRepresentation, NULL, &txn);
        if (err == 0) {
            err = sfs_longname_insert(txn, false, enc, longFull);
        }
    }
    if (err == 0) {
        switch (type) {
        case FSItemTypeDirectory:
            if (mkdirat(dirfd, enc, mode) != 0) {
                err = errno;
            }
            break;
        case FSItemTypeSymlink:
            if (symlinkat(linkTarget, dirfd, enc) != 0) {
                err = errno;
            }
            break;
        default: {
            int fd = openat(dirfd, enc, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, mode);
            if (fd < 0) {
                err = errno;
                break;
            }
            // Like securefs, write the file header at creation.
            sfs_file *file = NULL;
            err = sfs_file_open(fd, &_params, _verify, true, &file);
            sfs_file_close(file);
            close(fd);
            if (err) {
                unlinkat(dirfd, enc, 0);
            }
            break;
        }
        }
    }
    if (txn) {
        sfs_longname_end(txn, err == 0);
    }
    if (err == 0) {
        struct stat st;
        if (fstatat(dirfd, enc, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            err = errno;
        } else {
            item = [self itemForStat:&st parent:dir encryptedName:enc plainName:name];
            SFSLocation loc = {.dirfd = dirfd, .closeDir = NO, .name = enc};
            // The process umask affected the creation mode, so the requested attributes
            // (including the mode) are applied explicitly.
            int attrErr = [self applyAttributes:attributes toItem:item location:&loc creating:YES];
            if (attrErr) {
                SFSLogError("Applying attributes to a new item failed: %{darwin.errno}d", attrErr);
            }
            if (fstatat(dirfd, enc, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                attrs = [self attributesForStat:&st
                                           item:item
                                         itemID:item.itemID
                                       parentID:dir.itemID
                                       location:&loc];
            }
            dirAttrs = [self attributesOfItem:dir error:&attrErr];
        }
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    [self unlockNamespace];
    free(linkTarget);
    if (err == 0) {
        [self invalidateSnapshotOfDirectory:dir];
        if (!attrs || !dirAttrs) {
            err = EIO;
        }
    }
    completion(item, attrs, dirAttrs, err);
}

- (void)createItemNamed:(FSFileName *)name
                   type:(FSItemType)type
            inDirectory:(FSItem *)directory
             attributes:(FSItemSetAttributesRequest *)newAttributes
                context:(FSContext *)context
           replyHandler:(void (^)(FSCreateItemResult *, NSError *))reply
{
    if (type == FSItemTypeSymlink) {
        reply(nil, posixError(EINVAL));
        return;
    }
    [self createItemNamed:name
                     type:type
              inDirectory:(SFSItem *)directory
               attributes:newAttributes
             linkContents:nil
               completion:^(SFSItem *item, FSItemAttributes *attrs, FSItemAttributes *dirAttrs, int err) {
        if (err) {
            reply(nil, posixError(err));
            return;
        }
        reply([[FSCreateItemResult alloc] initWithNewItem:item
                                              newItemName:name
                                        newItemAttributes:attrs
                                      directoryAttributes:dirAttrs
                                                freeSpace:nil],
              nil);
    }];
}

- (void)createSymbolicLinkNamed:(FSFileName *)name
                    inDirectory:(FSItem *)directory
                     attributes:(FSItemSetAttributesRequest *)newAttributes
                   linkContents:(FSFileName *)contents
                        context:(FSContext *)context
                   replyHandler:(void (^)(FSCreateSymlinkResult *, NSError *))reply
{
    [self createItemNamed:name
                     type:FSItemTypeSymlink
              inDirectory:(SFSItem *)directory
               attributes:newAttributes
             linkContents:contents
               completion:^(SFSItem *item, FSItemAttributes *attrs, FSItemAttributes *dirAttrs, int err) {
        if (err) {
            reply(nil, posixError(err));
            return;
        }
        reply([[FSCreateSymlinkResult alloc] initWithNewItem:item
                                                 newItemName:name
                                           newItemAttributes:attrs
                                         directoryAttributes:dirAttrs
                                                   freeSpace:nil],
              nil);
    }];
}

- (void)createLinkToItem:(FSItem *)item
                   named:(FSFileName *)name
             inDirectory:(FSItem *)directory
                 context:(FSContext *)context
            replyHandler:(void (^)(FSCreateLinkResult *, NSError *))reply
{
    reply(nil, posixError(ENOTSUP));
}

/// Removes the long name table of a directory that is about to be deleted.
- (void)removeLongNameTableInDirectoryFD:(int)dirfd name:(const char *)enc
{
    int fd = openat(dirfd, enc, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    unlinkat(fd, SFS_LONG_NAME_TABLE_FILE_NAME, 0);
    unlinkat(fd, SFS_LONG_NAME_TABLE_FILE_NAME "-journal", 0);
    close(fd);
}

- (void)removeItem:(FSItem *)fsItem
             named:(FSFileName *)name
     fromDirectory:(FSItem *)directory
           context:(FSContext *)context
      replyHandler:(void (^)(FSRemoveItemResult *, NSError *))reply
{
    if (_readOnly) {
        reply(nil, posixError(EROFS));
        return;
    }
    SFSItem *item = (SFSItem *)fsItem;
    SFSItem *dir = (SFSItem *)directory;
    [self lockNamespaceShared];
    int dirfd = -1;
    int err = [self openDirectory:dir fd:&dirfd];
    FSItemAttributes *attrs = nil, *dirAttrs = nil;
    char enc[SFS_MAX_ENCRYPTED_COMPONENT];
    if (err == 0) {
        if (item.parent == dir && !item.removed) {
            strlcpy(enc, item.encryptedName.bytes, sizeof(enc));
        } else {
            struct stat ignored;
            FSFileName *stored = nil;
            err = [self resolveName:name inDirectory:dir dirFD:dirfd encryptedName:enc stat:&ignored storedName:&stored];
        }
    }
    if (err == 0) {
        attrs = [self attributesOfItem:item error:&err];
    }
    sfs_longname_txn *txn = NULL;
    if (err == 0 && [self isLongName:enc]) {
        NSString *table = [self longNameTablePathForDirectory:dir];
        err = sfs_longname_begin(table.fileSystemRepresentation, NULL, &txn);
        if (err == 0) {
            err = sfs_longname_remove(txn, enc);
        }
    }
    if (err == 0) {
        if (item.type == FSItemTypeDirectory) {
            [self removeLongNameTableInDirectoryFD:dirfd name:enc];
            if (unlinkat(dirfd, enc, AT_REMOVEDIR) != 0) {
                err = errno;
            }
        } else if (unlinkat(dirfd, enc, 0) != 0) {
            err = errno;
        }
    }
    if (txn) {
        sfs_longname_end(txn, err == 0);
    }
    if (err == 0) {
        int ignored = 0;
        dirAttrs = [self attributesOfItem:dir error:&ignored];
        if (attrs.linkCount > 0) {
            attrs.linkCount = item.type == FSItemTypeDirectory ? 0 : attrs.linkCount - 1;
        }
        if (attrs.linkCount == 0) {
            item.removed = YES;
            [self forgetItem:item];
        }
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    [self unlockNamespace];
    if (err == 0) {
        [self invalidateSnapshotOfDirectory:dir];
        if (!dirAttrs) {
            err = EIO;
        }
    }
    reply(err ? nil : [[FSRemoveItemResult alloc] initWithItemAttributes:attrs
                                                     directoryAttributes:dirAttrs
                                                               freeSpace:nil],
          err ? posixError(err) : nil);
}

- (void)renameItem:(FSItem *)fsItem
       inDirectory:(FSItem *)sourceDirectory
             named:(FSFileName *)sourceName
         toNewName:(FSFileName *)destinationName
       inDirectory:(FSItem *)destinationDirectory
          overItem:(FSItem *)fsOverItem
           context:(FSContext *)context
      replyHandler:(void (^)(FSRenameItemResult *, NSError *))reply
{
    if (_readOnly) {
        reply(nil, posixError(EROFS));
        return;
    }
    SFSItem *item = (SFSItem *)fsItem;
    SFSItem *srcDir = (SFSItem *)sourceDirectory;
    SFSItem *dstDir = (SFSItem *)destinationDirectory;
    SFSItem *overItem = (SFSItem *)fsOverItem;

    char dstEnc[SFS_MAX_ENCRYPTED_COMPONENT], dstLongFull[SFS_MAX_ENCRYPTED_COMPONENT];
    bool dstIsLong = false;
    FSFileName *newName = destinationName;
    int err = 0;
    if (overItem && overItem.parent == dstDir && !overItem.removed) {
        // Replace the existing entry exactly as stored (it may use another normalization form).
        strlcpy(dstEnc, overItem.encryptedName.bytes, sizeof(dstEnc));
        dstIsLong = [self isLongName:dstEnc];
        if (dstIsLong) {
            err = [self encryptNewName:destinationName encryptedName:dstEnc longFull:dstLongFull isLong:&dstIsLong];
        } else {
            newName = overItem.plainName;
        }
    } else {
        err = [self encryptNewName:destinationName encryptedName:dstEnc longFull:dstLongFull isLong:&dstIsLong];
    }
    if (err) {
        reply(nil, posixError(err));
        return;
    }

    [self lockNamespaceExclusive];
    int srcfd = -1, dstfd = -1;
    FSItemAttributes *attrs = nil, *srcAttrs = nil, *dstAttrs = nil, *overAttrs = nil;
    char srcEnc[SFS_MAX_ENCRYPTED_COMPONENT];
    if (item.parent == srcDir && !item.removed) {
        strlcpy(srcEnc, item.encryptedName.bytes, sizeof(srcEnc));
    } else {
        err = ENOENT;
    }
    if (err == 0) {
        err = [self openDirectory:srcDir fd:&srcfd];
    }
    if (err == 0) {
        err = [self openDirectory:dstDir fd:&dstfd];
    }
    if (err == 0 && overItem) {
        int ignored = 0;
        overAttrs = [self attributesOfItem:overItem error:&ignored];
    }
    bool srcIsLong = [self isLongName:srcEnc];
    sfs_longname_txn *txn = NULL;
    if (err == 0 && (srcIsLong || dstIsLong)) {
        NSString *srcTable = [self longNameTablePathForDirectory:srcDir];
        NSString *dstTable = [self longNameTablePathForDirectory:dstDir];
        err = sfs_longname_begin(srcTable.fileSystemRepresentation, dstTable.fileSystemRepresentation, &txn);
        if (err == 0 && srcIsLong) {
            err = sfs_longname_remove(txn, srcEnc);
        }
        if (err == 0 && dstIsLong) {
            err = sfs_longname_insert(txn, true, dstEnc, dstLongFull);
        }
    }
    if (err == 0) {
        if (overItem && overItem.type == FSItemTypeDirectory) {
            // An empty virtual directory may still hold a long name table.
            [self removeLongNameTableInDirectoryFD:dstfd name:dstEnc];
        }
        if (renameat(srcfd, srcEnc, dstfd, dstEnc) != 0) {
            err = errno;
        }
    }
    if (txn) {
        sfs_longname_end(txn, err == 0);
    }
    if (err == 0) {
        item.parent = dstDir;
        item.encryptedName = cStringData(dstEnc);
        item.plainName = newName;
        if (overItem && overItem != item) {
            overItem.removed = YES;
            [self forgetItem:overItem];
            if (overAttrs.linkCount > 0) {
                overAttrs.linkCount -= 1;
            }
        }
        int ignored = 0;
        attrs = [self attributesOfItem:item error:&ignored];
        srcAttrs = [self attributesOfItem:srcDir error:&ignored];
        dstAttrs = [self attributesOfItem:dstDir error:&ignored];
    }
    if (srcfd >= 0) {
        close(srcfd);
    }
    if (dstfd >= 0) {
        close(dstfd);
    }
    [self unlockNamespace];
    if (err == 0) {
        [self invalidateSnapshotOfDirectory:srcDir];
        if (dstDir != srcDir) {
            [self invalidateSnapshotOfDirectory:dstDir];
        }
        if (!attrs || !srcAttrs || !dstAttrs) {
            err = EIO;
        }
    }
    reply(err ? nil : [[FSRenameItemResult alloc] initWithNewName:newName
                                            renamedItemAttributes:attrs
                                        sourceDirectoryAttributes:srcAttrs
                                   destinationDirectoryAttributes:dstAttrs
                                               overItemAttributes:overAttrs
                                                        freeSpace:nil],
          err ? posixError(err) : nil);
}

/// Builds a decrypted listing of `dir`. Requires the namespace lock.
- (SFSDirectorySnapshot *)snapshotOfDirectory:(SFSItem *)dir dirFD:(int)dirfd error:(int *)outErr
{
    NSMutableArray<SFSDirectoryEntry *> *entries = [NSMutableArray array];
    int err = [self forEachEntryInDirectory:dir
                                      dirFD:dirfd
                                      block:^BOOL(const char *underlying, FSFileName *name, uint8_t dtype) {
        SFSDirectoryEntry *entry = [[SFSDirectoryEntry alloc] init];
        entry.name = name;
        entry.encryptedName = cStringData(underlying);
        // d_type may be DT_UNKNOWN and d_ino may differ from st_ino (e.g. for mount points);
        // fstatat gives the authoritative values used for item identifiers.
        struct stat st;
        if (fstatat(dirfd, underlying, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            return YES;
        }
        entry.type = itemTypeForMode(st.st_mode);
        entry.inode = st.st_ino;
        [entries addObject:entry];
        return YES;
    }];
    if (err) {
        *outErr = err;
        return nil;
    }
    SFSDirectorySnapshot *snapshot = [[SFSDirectorySnapshot alloc] init];
    snapshot.entries = entries;
    snapshot.verifier = atomic_fetch_add(&_verifierCounter, 1) + 1;
    return snapshot;
}

- (void)enumerateDirectory:(FSItem *)directory
          startingAtCookie:(FSDirectoryCookie)cookie
                  verifier:(FSDirectoryVerifier)verifier
       providingAttributes:(FSItemGetAttributesRequest *)attributes
               usingPacker:(FSDirectoryEntryPacker *)packer
                   context:(FSContext *)context
              replyHandler:(void (^)(FSEnumerateDirectoryResult *, NSError *))reply
{
    SFSItem *dir = (SFSItem *)directory;
    [self lockNamespaceShared];
    int dirfd = -1;
    int err = [self openDirectory:dir fd:&dirfd];
    SFSDirectorySnapshot *snapshot = nil;
    if (err == 0) {
        pthread_mutex_lock(dir.lock);
        snapshot = dir.snapshot;
        if (cookie == FSDirectoryCookieInitial || !snapshot || snapshot.verifier != verifier) {
            // Start over with a fresh listing. A continuation with a stale verifier resumes
            // at the same position of the new listing, which is the best we can do without
            // stable on-disk positions.
            snapshot = [self snapshotOfDirectory:dir dirFD:dirfd error:&err];
            dir.snapshot = snapshot;
        }
        pthread_mutex_unlock(dir.lock);
    }
    if (err == 0) {
        // Cookie layout: 0 = ".", 1 = "..", 2 + i = entries[i]. Each packed entry's cookie is
        // the position of the next one.
        NSArray<SFSDirectoryEntry *> *entries = snapshot.entries;
        uint64_t position = cookie;
        if (attributes && position < 2) {
            position = 2;
        }
        while (position < 2 + (uint64_t)entries.count) {
            BOOL packed;
            if (position < 2) {
                FSItemID dotID = dir.itemID;
                FSItemID dotdotID = dir.isRoot ? dir.itemID : [self parentIDOfItem:dir];
                packed = [packer packEntryWithName:[FSFileName nameWithString:position == 0 ? @"." : @".."]
                                          itemType:FSItemTypeDirectory
                                            itemID:position == 0 ? dotID : dotdotID
                                        nextCookie:position + 1
                                        attributes:nil];
            } else {
                SFSDirectoryEntry *entry = entries[(NSUInteger)(position - 2)];
                FSItemAttributes *attrs = nil;
                if (attributes) {
                    struct stat st;
                    if (fstatat(dirfd, entry.encryptedName.bytes, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                        // Vanished since the listing was made; skip it.
                        position += 1;
                        continue;
                    }
                    os_unfair_lock_lock(&_itemsLock);
                    SFSItem *cached = _items[@(st.st_ino)];
                    os_unfair_lock_unlock(&_itemsLock);
                    SFSLocation loc = {.dirfd = dirfd, .closeDir = NO, .name = entry.encryptedName.bytes};
                    attrs = [self attributesForStat:&st
                                               item:cached
                                             itemID:(FSItemID)st.st_ino
                                           parentID:dir.itemID
                                           location:&loc];
                }
                packed = [packer packEntryWithName:entry.name
                                          itemType:entry.type
                                            itemID:(FSItemID)entry.inode
                                        nextCookie:position + 1
                                        attributes:attrs];
            }
            if (!packed) {
                break;
            }
            position += 1;
        }
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    [self unlockNamespace];
    reply(err ? nil : [[FSEnumerateDirectoryResult alloc] initWithVerifier:snapshot.verifier],
          err ? posixError(err) : nil);
}

- (void)readSymbolicLink:(FSItem *)fsItem
                 context:(FSContext *)context
            replyHandler:(void (^)(FSReadSymlinkResult *, NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    [self lockNamespaceShared];
    SFSLocation loc;
    int err = [self locateItem:item location:&loc];
    FSFileName *contents = nil;
    FSItemAttributes *attrs = nil;
    if (err == 0) {
        char buf[PATH_MAX * 4];
        ssize_t n = readlinkat(loc.dirfd, loc.name, buf, sizeof(buf));
        if (n < 0) {
            err = errno;
        } else {
            char *plain = NULL;
            size_t plain_len = 0;
            err = sfs_names_decrypt_symlink(&_names, buf, (size_t)n, &plain, &plain_len);
            if (err == 0) {
                contents = [FSFileName nameWithBytes:plain length:plain_len];
                free(plain);
            }
        }
    }
    releaseLocation(&loc);
    if (err == 0) {
        attrs = [self attributesOfItem:item error:&err];
    }
    [self unlockNamespace];
    reply(err ? nil : [[FSReadSymlinkResult alloc] initWithContents:contents symlinkAttributes:attrs],
          err ? posixError(err) : nil);
}

#pragma mark - Open / close / read / write

/// Makes sure `item` has an open encrypted file, writable if requested.
/// Requires the namespace lock and the item lock.
- (int)ensureFileOfItem:(SFSItem *)item writable:(BOOL)writable
{
    if (item.file && (item.fdWritable || !writable)) {
        return 0;
    }
    if (item.type != FSItemTypeFile) {
        return item.type == FSItemTypeDirectory ? EISDIR : EINVAL;
    }
    SFSLocation loc;
    int err = [self locateItem:item location:&loc];
    if (err) {
        return err;
    }
    int flags = (writable ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC;
    int fd = openat(loc.dirfd, loc.name, flags);
    if (fd < 0) {
        err = errno;
    }
    releaseLocation(&loc);
    if (fd < 0) {
        return err;
    }
    if (item.file) {
        // Upgrade an existing read-only stream to a writable descriptor.
        sfs_file_set_fd(item.file, fd);
        close(item.fd);
    } else {
        sfs_file *file = NULL;
        err = sfs_file_open(fd, &_params, _verify, false, &file);
        if (err) {
            close(fd);
            return err;
        }
        item.file = file;
    }
    item.fd = fd;
    item.fdWritable = writable;
    return 0;
}

- (void)openItem:(FSItem *)fsItem
       withModes:(FSVolumeOpenModes)modes
         context:(FSContext *)context
    replyHandler:(void (^)(NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    if (item.type != FSItemTypeFile) {
        reply(nil);
        return;
    }
    BOOL writable = (modes & FSVolumeOpenModesWrite) != 0;
    if (writable && _readOnly) {
        reply(posixError(EROFS));
        return;
    }
    [self lockNamespaceShared];
    pthread_mutex_lock(item.lock);
    int err = [self ensureFileOfItem:item writable:writable];
    if (err == 0) {
        item.openModes |= modes;
    }
    pthread_mutex_unlock(item.lock);
    [self unlockNamespace];
    reply(err ? posixError(err) : nil);
}

- (void)closeItem:(FSItem *)fsItem
     keepingModes:(FSVolumeOpenModes)modes
          context:(FSContext *)context
     replyHandler:(void (^)(NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    pthread_mutex_lock(item.lock);
    if (modes == 0) {
        [item closeFileLocked];
    } else {
        item.openModes = modes;
    }
    pthread_mutex_unlock(item.lock);
    reply(nil);
}

/// Attributes of an item with an open file. Requires the namespace lock and the item lock.
- (FSItemAttributes *)attributesOfOpenItem:(SFSItem *)item
{
    struct stat st;
    if (fstat(item.fd, &st) != 0) {
        return nil;
    }
    FSItemAttributes *attrs = [self attributesForStat:&st
                                                 item:item
                                               itemID:item.itemID
                                             parentID:[self parentIDOfItem:item]
                                             location:NULL];
    uint64_t size = 0;
    if (sfs_file_size(item.file, &size) == 0) {
        attrs.size = size;
        if (sfs_file_padding(item.file) > 0 || size > 0) {
            item.cachedPadding = sfs_file_padding(item.file);
        }
    }
    return attrs;
}

- (void)readFromFile:(FSItem *)fsItem
              offset:(off_t)offset
              length:(size_t)length
          intoBuffer:(FSMutableFileDataBuffer *)buffer
        replyHandler:(void (^)(FSReadFileResult *, NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    if (offset < 0) {
        reply(nil, posixError(EINVAL));
        return;
    }
    size_t len = MIN(length, (size_t)buffer.length);
    size_t nread = 0;
    FSItemAttributes *attrs = nil;
    [self lockNamespaceShared];
    pthread_mutex_lock(item.lock);
    int err = [self ensureFileOfItem:item writable:NO];
    if (err == 0) {
        err = sfs_file_read(item.file, buffer.mutableBytes, (uint64_t)offset, len, &nread);
        if (err == EIO) {
            SFSLogError("Integrity check failed while reading inode %llu", item.inode);
        }
    }
    if (err == 0) {
        attrs = [self attributesOfOpenItem:item];
    }
    pthread_mutex_unlock(item.lock);
    [self unlockNamespace];
    if (err == 0 && !attrs) {
        err = EIO;
    }
    reply(err ? nil : [[FSReadFileResult alloc] initWithBytesRead:nread itemAttributes:attrs],
          err ? posixError(err) : nil);
}

- (void)writeContents:(NSData *)contents
               toFile:(FSItem *)fsItem
             atOffset:(off_t)offset
         replyHandler:(void (^)(FSWriteFileResult *, NSError *))reply
{
    if (_readOnly) {
        reply(nil, posixError(EROFS));
        return;
    }
    SFSItem *item = (SFSItem *)fsItem;
    if (offset < 0) {
        reply(nil, posixError(EINVAL));
        return;
    }
    FSItemAttributes *attrs = nil;
    [self lockNamespaceShared];
    pthread_mutex_lock(item.lock);
    int err = [self ensureFileOfItem:item writable:YES];
    if (err == 0) {
        err = sfs_file_write(item.file, contents.bytes, (uint64_t)offset, contents.length);
    }
    if (err == 0) {
        attrs = [self attributesOfOpenItem:item];
    }
    pthread_mutex_unlock(item.lock);
    [self unlockNamespace];
    if (err == 0 && !attrs) {
        err = EIO;
    }
    reply(err ? nil : [[FSWriteFileResult alloc] initWithBytesWritten:contents.length
                                                       itemAttributes:attrs
                                                            freeSpace:nil],
          err ? posixError(err) : nil);
}

#pragma mark - Extended attributes

- (BOOL)xattrOperationsInhibited
{
    return !_xattr;
}

/// Encrypted xattr name and the item's absolute path. Requires the namespace lock.
- (int)xattrTargetOfItem:(SFSItem *)item
                    name:(nullable FSFileName *)name
                    path:(char *)path
           encryptedName:(char *)encName
{
    if (item.removed) {
        return ENOENT;
    }
    NSString *abs = [self absolutePathOfItem:item];
    if (strlcpy(path, abs.fileSystemRepresentation, PATH_MAX) >= PATH_MAX) {
        return ENAMETOOLONG;
    }
    if (name) {
        NSData *data = name.data;
        if (data.length == 0 || memchr(data.bytes, '\0', data.length)) {
            return EINVAL;
        }
        return sfs_xattr_encrypt_name(&_params, data.bytes, data.length, encName, XATTR_MAXNAMELEN * 4);
    }
    return 0;
}

- (void)getXattrNamed:(FSFileName *)name
               ofItem:(FSItem *)fsItem
              context:(FSContext *)context
         replyHandler:(void (^)(FSGetXattrResult *, NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    char path[PATH_MAX], encName[XATTR_MAXNAMELEN * 4];
    [self lockNamespaceShared];
    int err = [self xattrTargetOfItem:item name:name path:path encryptedName:encName];
    [self unlockNamespace];
    NSData *value = nil;
    while (err == 0) {
        ssize_t size = getxattr(path, encName, NULL, 0, 0, XATTR_NOFOLLOW);
        if (size < 0) {
            err = errno;
            break;
        }
        NSMutableData *raw = [NSMutableData dataWithLength:(NSUInteger)size];
        ssize_t got = getxattr(path, encName, raw.mutableBytes, raw.length, 0, XATTR_NOFOLLOW);
        if (got < 0) {
            err = errno;
            if (err == ERANGE) {
                // Grew in between; retry.
                err = 0;
                continue;
            }
            break;
        }
        NSMutableData *plain = [NSMutableData dataWithLength:(NSUInteger)got];
        size_t plainLen = 0;
        err = sfs_xattr_decrypt_value(&_params, _verify, raw.bytes, (size_t)got, plain.mutableBytes, &plainLen);
        if (err == 0) {
            plain.length = plainLen;
            value = plain;
        }
        break;
    }
    reply(err ? nil : [[FSGetXattrResult alloc] initWithXattrValue:value], err ? posixError(err) : nil);
}

- (void)setXattrNamed:(FSFileName *)name
               toData:(NSData *)value
               onItem:(FSItem *)fsItem
               policy:(FSSetXattrPolicy)policy
              context:(FSContext *)context
         replyHandler:(void (^)(FSSetXattrResult *, NSError *))reply
{
    if (_readOnly) {
        reply(nil, posixError(EROFS));
        return;
    }
    SFSItem *item = (SFSItem *)fsItem;
    char path[PATH_MAX], encName[XATTR_MAXNAMELEN * 4];
    [self lockNamespaceShared];
    int err = [self xattrTargetOfItem:item name:name path:path encryptedName:encName];
    [self unlockNamespace];
    if (err == 0) {
        if (policy == FSSetXattrPolicyDelete) {
            if (removexattr(path, encName, XATTR_NOFOLLOW) != 0) {
                err = errno;
            }
        } else {
            int options = XATTR_NOFOLLOW;
            if (policy == FSSetXattrPolicyMustCreate) {
                options |= XATTR_CREATE;
            } else if (policy == FSSetXattrPolicyMustReplace) {
                options |= XATTR_REPLACE;
            }
            NSMutableData *enc = [NSMutableData dataWithLength:sfs_xattr_encrypted_size(&_params, value.length)];
            err = sfs_xattr_encrypt_value(&_params, value.bytes, value.length, enc.mutableBytes);
            if (err == 0 && setxattr(path, encName, enc.bytes, enc.length, 0, options) != 0) {
                err = errno;
            }
        }
    }
    reply(err ? nil : [[FSSetXattrResult alloc] initWithFreeSpace:nil], err ? posixError(err) : nil);
}

- (void)listXattrsOfItem:(FSItem *)fsItem
                 context:(FSContext *)context
            replyHandler:(void (^)(FSListXattrsResult *, NSError *))reply
{
    SFSItem *item = (SFSItem *)fsItem;
    char path[PATH_MAX];
    [self lockNamespaceShared];
    int err = [self xattrTargetOfItem:item name:nil path:path encryptedName:NULL];
    [self unlockNamespace];
    NSMutableArray<FSFileName *> *names = [NSMutableArray array];
    while (err == 0) {
        ssize_t size = listxattr(path, NULL, 0, XATTR_NOFOLLOW);
        if (size < 0) {
            err = errno;
            break;
        }
        NSMutableData *buf = [NSMutableData dataWithLength:(NSUInteger)size + 1];
        ssize_t got = listxattr(path, buf.mutableBytes, (size_t)size, XATTR_NOFOLLOW);
        if (got < 0) {
            err = errno == ERANGE ? 0 : errno;
            if (err == 0) {
                continue;
            }
            break;
        }
        const char *p = buf.bytes, *end = p + got;
        char plain[XATTR_MAXNAMELEN * 4];
        while (p < end) {
            size_t len = strnlen(p, (size_t)(end - p));
            size_t plainLen = 0;
            if (sfs_xattr_decrypt_name(&_params, p, len, plain, sizeof(plain), &plainLen)) {
                [names addObject:[FSFileName nameWithBytes:plain length:plainLen]];
            }
            p += len + 1;
        }
        break;
    }
    reply(err ? nil : [[FSListXattrsResult alloc] initWithXattrNames:names], err ? posixError(err) : nil);
}

@end
