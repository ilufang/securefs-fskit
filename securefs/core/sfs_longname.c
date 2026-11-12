//
//  sfs_longname.c
//  securefs
//

#include "sfs_longname.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

struct sfs_longname_txn {
    sqlite3 *db;
    bool has_secondary;
};

static const char kCreateMain[] = "create table if not exists main.encrypted_mappings ("
                                  "keyed_hash text not null primary key, "
                                  "encrypted_name text not null);";
static const char kCreateSecondary[] = "create table if not exists secondary.encrypted_mappings ("
                                       "keyed_hash text not null primary key, "
                                       "encrypted_name text not null);";

static int open_db(const char *path, bool readonly, sqlite3 **out)
{
    int flags = SQLITE_OPEN_NOMUTEX
        | (readonly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE));
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return rc == SQLITE_CANTOPEN ? ENOENT : EIO;
    }
    sqlite3_busy_timeout(db, 2000);
    *out = db;
    return 0;
}

static int run_text_statement(sqlite3 *db, const char *sql, const char *a, const char *b)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return EIO;
    }
    if (a) {
        sqlite3_bind_text(stmt, 1, a, -1, SQLITE_TRANSIENT);
    }
    if (b) {
        sqlite3_bind_text(stmt, 2, b, -1, SQLITE_TRANSIENT);
    }
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE || rc == SQLITE_ROW ? 0 : EIO;
}

int sfs_longname_lookup(const char *db_path, const char *hash, char *out, size_t cap)
{
    sqlite3 *db = NULL;
    int err = open_db(db_path, true, &db);
    if (err) {
        return err;
    }
    sqlite3_stmt *stmt = NULL;
    err = EIO;
    if (sqlite3_prepare_v2(db, "select encrypted_name from encrypted_mappings where keyed_hash = ?;",
                           -1, &stmt, NULL)
        == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            const unsigned char *text = sqlite3_column_text(stmt, 0);
            int len = sqlite3_column_bytes(stmt, 0);
            if (text && (size_t)len < cap) {
                memcpy(out, text, (size_t)len);
                out[len] = '\0';
                err = 0;
            }
        } else if (rc == SQLITE_DONE) {
            err = ENOENT;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return err;
}

int sfs_longname_begin(const char *db_path, const char *secondary_db_path,
                       sfs_longname_txn **out)
{
    *out = NULL;
    sfs_longname_txn *txn = calloc(1, sizeof(*txn));
    if (!txn) {
        return ENOMEM;
    }
    int err = open_db(db_path, false, &txn->db);
    if (err) {
        free(txn);
        return err;
    }
    err = run_text_statement(txn->db, kCreateMain, NULL, NULL);
    if (!err && secondary_db_path && strcmp(secondary_db_path, db_path) != 0) {
        err = run_text_statement(txn->db, "attach database ? as secondary;", secondary_db_path,
                                 NULL);
        if (!err) {
            txn->has_secondary = true;
            err = run_text_statement(txn->db, kCreateSecondary, NULL, NULL);
        }
    }
    if (!err) {
        err = run_text_statement(txn->db, "begin;", NULL, NULL);
    }
    if (err) {
        sqlite3_close(txn->db);
        free(txn);
        return err;
    }
    *out = txn;
    return 0;
}

int sfs_longname_insert(sfs_longname_txn *txn, bool secondary, const char *hash,
                        const char *encrypted_name)
{
    const char *sql = secondary && txn->has_secondary
        ? "insert or ignore into secondary.encrypted_mappings (keyed_hash, encrypted_name) "
          "values (?, ?);"
        : "insert or ignore into main.encrypted_mappings (keyed_hash, encrypted_name) "
          "values (?, ?);";
    return run_text_statement(txn->db, sql, hash, encrypted_name);
}

int sfs_longname_remove(sfs_longname_txn *txn, const char *hash)
{
    return run_text_statement(txn->db, "delete from main.encrypted_mappings where keyed_hash = ?;",
                              hash, NULL);
}

int sfs_longname_end(sfs_longname_txn *txn, bool commit)
{
    if (!txn) {
        return 0;
    }
    int err = run_text_statement(txn->db, commit ? "commit;" : "rollback;", NULL, NULL);
    sqlite3_close(txn->db);
    free(txn);
    return err;
}
