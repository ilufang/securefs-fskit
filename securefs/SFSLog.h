//
//  SFSLog.h
//  securefs
//
//  Unified logging for the extension. View with:
//    log stream --predicate 'subsystem == "com.ilufang.securefs-fskit"'
//

#ifndef SFSLog_h
#define SFSLog_h

#include <os/log.h>

static inline os_log_t sfs_log(void)
{
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.ilufang.securefs-fskit", "fs");
    });
    return log;
}

#define SFSLogInfo(fmt, ...) os_log_info(sfs_log(), fmt, ##__VA_ARGS__)
#define SFSLogError(fmt, ...) os_log_error(sfs_log(), fmt, ##__VA_ARGS__)
#define SFSLogDebug(fmt, ...) os_log_debug(sfs_log(), fmt, ##__VA_ARGS__)

#endif /* SFSLog_h */
