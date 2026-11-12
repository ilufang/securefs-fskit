//
//  sfs_stream.h
//  securefs
//
//  The lite format content stream (securefs' lite::AESGCMCryptStream on top of
//  BlockBasedStream), operating directly on a file descriptor.
//
//  Physical layout of an underlying file:
//    [16-byte file id][padding bytes][block 0][block 1]...
//  where each block is [IV (iv_size)][ciphertext (<= block_size)][GCM tag (16)].
//  The per-file key is AES-256-ECB(content_key, id); the associated data of a
//  block is its little-endian 32-bit block number followed by the padding bytes.
//  An all-zero physical block decodes to an all-zero plaintext block (sparse files).
//

#ifndef SFS_STREAM_H
#define SFS_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "sfs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SFS_FILE_ID_SIZE 16

/// An open encrypted file. Not thread safe; callers serialize access.
typedef struct sfs_file sfs_file;

/// Wraps `fd` (not owned; the caller closes it after sfs_file_close).
/// An empty underlying file has no header yet; one is written on the first
/// mutation (or immediately when `write_header_if_empty` is set).
/// Returns 0 or an errno value (EIO for a corrupted header).
int sfs_file_open(int fd, const sfs_params *params, bool verify, bool write_header_if_empty,
                  sfs_file **out);
void sfs_file_close(sfs_file *file);

/// Replaces the descriptor used for I/O, e.g. after reopening read-write.
void sfs_file_set_fd(sfs_file *file, int fd);

/// The plaintext size.
int sfs_file_size(sfs_file *file, uint64_t *out_size);

/// Reads up to `len` bytes at `offset`. Short reads only happen at end of file.
int sfs_file_read(sfs_file *file, void *buf, uint64_t offset, size_t len, size_t *out_read);

/// Writes `len` bytes at `offset`, zero filling any gap past the current end.
int sfs_file_write(sfs_file *file, const void *buf, uint64_t offset, size_t len);

/// Truncates or extends to `new_size`.
int sfs_file_resize(sfs_file *file, uint64_t new_size);

/// Number of padding bytes after the file id (0 if the header doesn't exist yet).
uint32_t sfs_file_padding(const sfs_file *file);

/// The plaintext size implied by a physical size, valid only when the repository has
/// no padding (max_padding == 0). Mirrors AESGCMCryptStream::calculate_real_size.
uint64_t sfs_virtual_size_from_physical(const sfs_params *params, uint64_t physical_size);

/// The plaintext size of a file given its physical size and padding size.
uint64_t sfs_virtual_size_with_padding(const sfs_params *params, uint64_t physical_size,
                                       uint32_t padding);

/// Computes the padding size of a file from its id (0 when padding is disabled).
uint32_t sfs_compute_padding(const sfs_params *params, const uint8_t id[SFS_FILE_ID_SIZE]);

/// Reads the header of the file at `fd` and returns its padding size.
/// An empty file reports 0. Returns 0 or an errno value.
int sfs_read_padding(int fd, const sfs_params *params, uint32_t *out_padding);

#ifdef __cplusplus
}
#endif

#endif /* SFS_STREAM_H */
