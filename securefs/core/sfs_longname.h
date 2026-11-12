//
//  sfs_longname.h
//  securefs
//
//  The per-directory `.long_names.db` SQLite table that maps the hashed on-disk
//  name of a long component to its encrypted full name. Ported from securefs'
//  lite_long_name_lookup_table.cpp; the schema is shared with securefs:
//
//    create table encrypted_mappings (
//        keyed_hash text not null primary key,
//        encrypted_name text not null);
//
//  Mutations run in a transaction that the caller commits only after the
//  corresponding file system operation succeeded.
//

#ifndef SFS_LONGNAME_H
#define SFS_LONGNAME_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sfs_longname_txn sfs_longname_txn;

/// Looks up the encrypted full name for `hash`. Returns 0, ENOENT, or EIO.
int sfs_longname_lookup(const char *db_path, const char *hash, char *out, size_t cap);

/// Opens `db_path` (creating it) and begins a transaction. When `secondary_db_path` is
/// non-NULL and different, it is attached so a rename can update both atomically.
int sfs_longname_begin(const char *db_path, const char *secondary_db_path,
                       sfs_longname_txn **out);

/// Inserts a mapping (insert or ignore). `secondary` selects the attached database.
int sfs_longname_insert(sfs_longname_txn *txn, bool secondary, const char *hash,
                        const char *encrypted_name);

/// Removes a mapping from the main database.
int sfs_longname_remove(sfs_longname_txn *txn, const char *hash);

/// Commits or rolls back, then closes. Returns the commit result.
int sfs_longname_end(sfs_longname_txn *txn, bool commit);

#ifdef __cplusplus
}
#endif

#endif /* SFS_LONGNAME_H */
