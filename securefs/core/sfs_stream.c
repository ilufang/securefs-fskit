//
//  sfs_stream.c
//  securefs
//
//  Port of securefs' lite::AESGCMCryptStream and BlockBasedStream. See sfs_stream.h.
//

#include "sfs_stream.h"
#include "sfs_crypto.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/// NIST recommends at most 2^32 IVs per AES-GCM key, so files are limited to
/// 2^31 - 1 blocks to leave room for overwrites.
static const uint64_t kMaxBlocks = (1ULL << 31) - 1;

struct sfs_file {
    int fd;
    sfs_params params;
    bool verify;
    bool has_header;
    uint8_t id[SFS_FILE_ID_SIZE];
    uint32_t padding;
    /// Associated data: 4-byte little endian block number followed by the padding bytes.
    uint8_t *aux;
    size_t aux_len;
    sfs_gcm *gcm;
    uint8_t *scratch;
    size_t scratch_cap;
};

#pragma mark - Helpers

static uint64_t underlying_block_size(const sfs_params *p)
{
    return (uint64_t)p->block_size + p->iv_size + SFS_GCM_TAG_SIZE;
}

static uint64_t header_size(const sfs_file *f)
{
    return SFS_FILE_ID_SIZE + f->padding;
}

static bool is_all_zeros(const uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (p[i]) {
            return false;
        }
    }
    return true;
}

/// Reads until `len` bytes or end of file. Returns bytes read or -errno.
static ssize_t pread_full(int fd, void *buf, size_t len, uint64_t offset)
{
    size_t done = 0;
    while (done < len) {
        ssize_t rc = pread(fd, (uint8_t *)buf + done, len - done, (off_t)(offset + done));
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (rc == 0) {
            break;
        }
        done += (size_t)rc;
    }
    return (ssize_t)done;
}

static int pwrite_full(int fd, const void *buf, size_t len, uint64_t offset)
{
    size_t done = 0;
    while (done < len) {
        ssize_t rc = pwrite(fd, (const uint8_t *)buf + done, len - done, (off_t)(offset + done));
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        done += (size_t)rc;
    }
    return 0;
}

static int physical_size(int fd, uint64_t *out)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        return errno;
    }
    *out = (uint64_t)st.st_size;
    return 0;
}

static uint8_t *scratch(sfs_file *f, size_t len)
{
    if (len > f->scratch_cap) {
        uint8_t *p = realloc(f->scratch, len);
        if (!p) {
            return NULL;
        }
        f->scratch = p;
        f->scratch_cap = len;
    }
    return f->scratch;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

uint32_t sfs_compute_padding(const sfs_params *params, const uint8_t id[SFS_FILE_ID_SIZE])
{
    if (params->max_padding == 0 || !params->has_padding_key) {
        return 0;
    }
    uint8_t transformed[16];
    if (!sfs_aes256_ecb_block(params->padding_key, id, transformed)) {
        return 0;
    }
    // Interpret the block as a big-endian unsigned 128-bit integer.
    unsigned __int128 value = 0;
    for (int i = 0; i < 16; ++i) {
        value = (value << 8) | transformed[i];
    }
    return (uint32_t)(value % ((unsigned __int128)params->max_padding + 1));
}

uint64_t sfs_virtual_size_from_physical(const sfs_params *params, uint64_t physical)
{
    uint64_t ub = underlying_block_size(params);
    uint64_t overhead = (uint64_t)params->iv_size + SFS_GCM_TAG_SIZE;
    if (physical <= SFS_FILE_ID_SIZE) {
        return 0;
    }
    physical -= SFS_FILE_ID_SIZE;
    uint64_t blocks = physical / ub, residue = physical % ub;
    return blocks * params->block_size + (residue > overhead ? residue - overhead : 0);
}

uint64_t sfs_virtual_size_with_padding(const sfs_params *params, uint64_t physical,
                                       uint32_t padding)
{
    if (physical <= SFS_FILE_ID_SIZE + (uint64_t)padding) {
        return 0;
    }
    return sfs_virtual_size_from_physical(params, physical - padding);
}

int sfs_read_padding(int fd, const sfs_params *params, uint32_t *out_padding)
{
    *out_padding = 0;
    if (params->max_padding == 0) {
        return 0;
    }
    uint8_t id[SFS_FILE_ID_SIZE];
    ssize_t rc = pread_full(fd, id, sizeof(id), 0);
    if (rc < 0) {
        return (int)-rc;
    }
    if (rc == 0) {
        return 0;
    }
    if (rc != SFS_FILE_ID_SIZE) {
        return EIO;
    }
    *out_padding = sfs_compute_padding(params, id);
    return 0;
}

#pragma mark - Header

/// Derives the per-file key and associated data buffer once `id` and `padding` are known.
static int init_from_id(sfs_file *f)
{
    uint8_t session_key[16];
    if (!sfs_aes256_ecb_block(f->params.content_key, f->id, session_key)) {
        return EIO;
    }
    sfs_gcm_free(f->gcm);
    f->gcm = sfs_gcm_new(session_key, sizeof(session_key), f->params.iv_size);
    sfs_secure_zero(session_key, sizeof(session_key));
    if (!f->gcm) {
        return ENOMEM;
    }
    f->has_header = true;
    return 0;
}

static int alloc_aux(sfs_file *f)
{
    free(f->aux);
    f->aux_len = sizeof(uint32_t) + f->padding;
    f->aux = calloc(1, f->aux_len);
    return f->aux ? 0 : ENOMEM;
}

/// Loads an existing header. Sets has_header only if the file has one.
static int load_header(sfs_file *f)
{
    ssize_t rc = pread_full(f->fd, f->id, SFS_FILE_ID_SIZE, 0);
    if (rc < 0) {
        return (int)-rc;
    }
    if (rc == 0) {
        return 0;
    }
    if (rc != SFS_FILE_ID_SIZE) {
        return EIO;
    }
    f->padding = sfs_compute_padding(&f->params, f->id);
    int err = alloc_aux(f);
    if (err) {
        return err;
    }
    if (f->padding > 0) {
        rc = pread_full(f->fd, f->aux + sizeof(uint32_t), f->padding, SFS_FILE_ID_SIZE);
        if (rc < 0) {
            return (int)-rc;
        }
        if ((size_t)rc != f->padding) {
            return EIO;
        }
    }
    return init_from_id(f);
}

static int create_header(sfs_file *f)
{
    sfs_random(f->id, SFS_FILE_ID_SIZE);
    int err = pwrite_full(f->fd, f->id, SFS_FILE_ID_SIZE, 0);
    if (err) {
        return err;
    }
    f->padding = sfs_compute_padding(&f->params, f->id);
    err = alloc_aux(f);
    if (err) {
        return err;
    }
    if (f->padding > 0) {
        sfs_random(f->aux, f->aux_len);
        err = pwrite_full(f->fd, f->aux + sizeof(uint32_t), f->padding, SFS_FILE_ID_SIZE);
        if (err) {
            return err;
        }
    }
    return init_from_id(f);
}

/// Makes sure the header exists before a mutation. Another writer may have created
/// it since this stream was opened, so try loading first.
static int ensure_header(sfs_file *f)
{
    if (f->has_header) {
        return 0;
    }
    int err = load_header(f);
    if (err || f->has_header) {
        return err;
    }
    return create_header(f);
}

int sfs_file_open(int fd, const sfs_params *params, bool verify, bool write_header_if_empty,
                  sfs_file **out)
{
    *out = NULL;
    if (!sfs_params_valid(params)) {
        return EINVAL;
    }
    sfs_file *f = calloc(1, sizeof(*f));
    if (!f) {
        return ENOMEM;
    }
    f->fd = fd;
    f->params = *params;
    f->verify = verify;
    int err = load_header(f);
    if (!err && !f->has_header && write_header_if_empty) {
        err = create_header(f);
    }
    if (err) {
        sfs_file_close(f);
        return err;
    }
    *out = f;
    return 0;
}

void sfs_file_close(sfs_file *f)
{
    if (!f) {
        return;
    }
    sfs_gcm_free(f->gcm);
    free(f->aux);
    if (f->scratch) {
        sfs_secure_zero(f->scratch, f->scratch_cap);
        free(f->scratch);
    }
    sfs_secure_zero(f, sizeof(*f));
    free(f);
}

void sfs_file_set_fd(sfs_file *f, int fd)
{
    f->fd = fd;
}

uint32_t sfs_file_padding(const sfs_file *f)
{
    return f->has_header ? f->padding : 0;
}

int sfs_file_size(sfs_file *f, uint64_t *out_size)
{
    uint64_t phys = 0;
    int err = physical_size(f->fd, &phys);
    if (err) {
        return err;
    }
    if (!f->has_header && phys > 0) {
        err = load_header(f);
        if (err) {
            return err;
        }
    }
    if (!f->has_header || phys <= header_size(f)) {
        *out_size = 0;
        return 0;
    }
    *out_size = sfs_virtual_size_from_physical(&f->params, phys - f->padding);
    return 0;
}

#pragma mark - Block level

/// Decrypts blocks [start, end) into `out`, which must hold (end - start) * block_size
/// bytes. Returns the number of plaintext bytes, which is short at end of file, or -errno.
static int64_t read_blocks(sfs_file *f, uint64_t start, uint64_t end, uint8_t *out)
{
    if (end > kMaxBlocks) {
        return -EFBIG;
    }
    if (end <= start || !f->has_header) {
        return 0;
    }
    const uint64_t ub = underlying_block_size(&f->params);
    const size_t iv_size = f->params.iv_size;
    const size_t overhead = iv_size + SFS_GCM_TAG_SIZE;
    size_t len = (size_t)((end - start) * ub);
    uint8_t *buf = scratch(f, len);
    if (!buf) {
        return -ENOMEM;
    }
    ssize_t rc = pread_full(f->fd, buf, len, header_size(f) + start * ub);
    if (rc < 0) {
        return rc;
    }
    int64_t total = 0;
    for (size_t i = 0; i < (size_t)rc; i += ub) {
        size_t chunk = (size_t)rc - i < ub ? (size_t)rc - i : (size_t)ub;
        if (chunk <= overhead) {
            break;
        }
        size_t virt = chunk - overhead;
        const uint8_t *p = buf + i;
        if (is_all_zeros(p, chunk)) {
            // Holes in sparse files.
            memset(out, 0, virt);
        } else {
            put_le32(f->aux, (uint32_t)(start + i / ub));
            bool ok = sfs_gcm_decrypt(f->gcm, p, f->aux, f->aux_len, p + iv_size, virt,
                                      p + chunk - SFS_GCM_TAG_SIZE, out);
            if (!ok && f->verify) {
                return -EIO;
            }
        }
        total += virt;
        out += virt;
    }
    return total;
}

/// Encrypts full blocks [start, end) followed by a partial block of `end_residue` bytes.
static int write_blocks(sfs_file *f, uint64_t start, uint64_t end, uint64_t end_residue,
                        const uint8_t *in)
{
    if (end > kMaxBlocks) {
        return EFBIG;
    }
    const uint64_t ub = underlying_block_size(&f->params);
    const size_t iv_size = f->params.iv_size;
    const size_t overhead = iv_size + SFS_GCM_TAG_SIZE;
    size_t len = (size_t)((end - start) * ub + (end_residue > 0 ? end_residue + overhead : 0));
    if (len == 0) {
        return 0;
    }
    uint8_t *buf = scratch(f, len);
    if (!buf) {
        return ENOMEM;
    }
    uint64_t block = start;
    for (size_t i = 0; i < len; ++block) {
        size_t chunk = len - i < ub ? len - i : (size_t)ub;
        size_t virt = chunk - overhead;
        uint8_t *p = buf + i;
        put_le32(f->aux, (uint32_t)block);
        // An all-zero IV is reserved because all-zero blocks denote holes.
        do {
            sfs_random(p, iv_size);
        } while (is_all_zeros(p, iv_size));
        if (!sfs_gcm_encrypt(f->gcm, p, f->aux, f->aux_len, in, virt, p + iv_size,
                             p + chunk - SFS_GCM_TAG_SIZE)) {
            return EIO;
        }
        in += virt;
        i += chunk;
    }
    return pwrite_full(f->fd, buf, len, header_size(f) + start * ub);
}

static int adjust_physical_size(sfs_file *f, uint64_t length)
{
    const uint64_t bs = f->params.block_size;
    uint64_t blocks = length / bs, residue = length % bs;
    uint64_t physical = header_size(f) + blocks * underlying_block_size(&f->params)
        + (residue > 0 ? residue + f->params.iv_size + SFS_GCM_TAG_SIZE : 0);
    if (ftruncate(f->fd, (off_t)physical) != 0) {
        return errno;
    }
    return 0;
}

#pragma mark - Byte level (BlockBasedStream)

int sfs_file_read(sfs_file *f, void *output, uint64_t offset, size_t len, size_t *out_read)
{
    *out_read = 0;
    if (len == 0) {
        return 0;
    }
    if (!f->has_header) {
        int err = load_header(f);
        if (err || !f->has_header) {
            return err;
        }
    }
    const uint64_t bs = f->params.block_size;
    uint64_t start_block = offset / bs, start_residue = offset % bs;
    uint64_t end_block = (offset + len) / bs, end_residue = (offset + len) % bs;
    if (start_residue == 0 && end_residue == 0) {
        int64_t rc = read_blocks(f, start_block, end_block, output);
        if (rc < 0) {
            return (int)-rc;
        }
        *out_read = (size_t)rc;
        return 0;
    }
    uint64_t nblocks = end_block - start_block + (end_residue > 0);
    uint8_t *buf = malloc((size_t)(nblocks * bs));
    if (!buf) {
        return ENOMEM;
    }
    int64_t rc = read_blocks(f, start_block, start_block + nblocks, buf);
    if (rc < 0) {
        free(buf);
        return (int)-rc;
    }
    if ((uint64_t)rc > start_residue) {
        uint64_t copy = (uint64_t)rc - start_residue;
        if (copy > len) {
            copy = len;
        }
        memcpy(output, buf + start_residue, (size_t)copy);
        *out_read = (size_t)copy;
    }
    sfs_secure_zero(buf, (size_t)(nblocks * bs));
    free(buf);
    return 0;
}

/// Writes `data` (or zeros when NULL) at `offset` without extending gaps first.
static int unchecked_write(sfs_file *f, const uint8_t *data, uint64_t offset, uint64_t len)
{
    if (len == 0) {
        return 0;
    }
    const uint64_t bs = f->params.block_size;
    uint64_t start_block = offset / bs, start_residue = offset % bs;
    uint64_t end_block = (offset + len) / bs, end_residue = (offset + len) % bs;
    if (start_residue == 0 && end_residue == 0 && data) {
        return write_blocks(f, start_block, end_block, 0, data);
    }
    // Read-modify-write the partial blocks at either end.
    uint64_t nblocks = end_block - start_block + (end_residue > 0);
    size_t buf_len = (size_t)(nblocks * bs);
    uint8_t *buf = calloc(1, buf_len);
    if (!buf) {
        return ENOMEM;
    }
    int err = 0;
    if (start_residue > 0 && start_block < end_block) {
        int64_t rc = read_blocks(f, start_block, start_block + 1, buf);
        if (rc < 0) {
            err = (int)-rc;
            goto out;
        }
    }
    uint64_t effective_end_residue = 0;
    if (end_residue > 0) {
        int64_t rc = read_blocks(f, end_block, end_block + 1, buf + (end_block - start_block) * bs);
        if (rc < 0) {
            err = (int)-rc;
            goto out;
        }
        effective_end_residue = (uint64_t)rc > end_residue ? (uint64_t)rc : end_residue;
    }
    if (data) {
        memcpy(buf + start_residue, data, (size_t)len);
    } else {
        memset(buf + start_residue, 0, (size_t)len);
    }
    err = write_blocks(f, start_block, end_block, effective_end_residue, buf);
out:
    sfs_secure_zero(buf, buf_len);
    free(buf);
    return err;
}

static int unchecked_resize(sfs_file *f, uint64_t current, uint64_t new_size)
{
    const uint64_t bs = f->params.block_size;
    int err = 0;
    if (new_size == current) {
        return 0;
    } else if (new_size < current) {
        uint64_t residue = new_size % bs, block = new_size / bs;
        if (residue > 0) {
            // Re-encrypt the new final partial block so its tag covers only the kept bytes.
            uint8_t *buf = calloc(1, (size_t)bs);
            if (!buf) {
                return ENOMEM;
            }
            int64_t rc = read_blocks(f, block, block + 1, buf);
            err = rc < 0 ? (int)-rc : write_blocks(f, block, block, residue, buf);
            sfs_secure_zero(buf, (size_t)bs);
            free(buf);
            if (err) {
                return err;
            }
        }
    } else {
        // Underlying files are sparse: only the current last block needs explicit zeros;
        // blocks beyond it are holes, which decode as zeros.
        uint64_t old_block = current / bs, new_block = new_size / bs;
        if (old_block == new_block) {
            err = unchecked_write(f, NULL, current, new_size - current);
        } else {
            err = unchecked_write(f, NULL, current, old_block * bs + bs - current);
        }
        if (err) {
            return err;
        }
    }
    return adjust_physical_size(f, new_size);
}

int sfs_file_write(sfs_file *f, const void *input, uint64_t offset, size_t len)
{
    if (len == 0) {
        return 0;
    }
    if ((offset + len) / f->params.block_size >= kMaxBlocks) {
        return EFBIG;
    }
    int err = ensure_header(f);
    if (err) {
        return err;
    }
    uint64_t current = 0;
    err = sfs_file_size(f, &current);
    if (err) {
        return err;
    }
    if (offset > current) {
        err = unchecked_resize(f, current, offset);
        if (err) {
            return err;
        }
    }
    return unchecked_write(f, input, offset, len);
}

int sfs_file_resize(sfs_file *f, uint64_t new_size)
{
    if (new_size / f->params.block_size >= kMaxBlocks) {
        return EFBIG;
    }
    uint64_t current = 0;
    int err = sfs_file_size(f, &current);
    if (err) {
        return err;
    }
    if (current == new_size) {
        return 0;
    }
    err = ensure_header(f);
    if (err) {
        return err;
    }
    return unchecked_resize(f, current, new_size);
}
