//
//  sfs_config_json.h
//  securefs
//
//  Parses `.securefs.json` into an sfs_legacy_config. Implemented with
//  NSJSONSerialization but exposed as a C interface.
//

#ifndef SFS_CONFIG_JSON_H
#define SFS_CONFIG_JSON_H

#include "sfs_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Returns 0 on success or EINVAL if the data isn't a valid securefs JSON config.
int sfs_legacy_config_parse_json(const void *data, size_t len, sfs_legacy_config *out);

#ifdef __cplusplus
}
#endif

#endif /* SFS_CONFIG_JSON_H */
