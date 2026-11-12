//
//  securefs.m
//  securefs
//
//  Created by Fang Lu on 11/12/26.
//

#import "securefs.h"

@implementation SecureFS

- (void)probeResource:(FSResource *)resource
         replyHandler:(void (^)(FSProbeResult * _Nullable,
                                NSError * _Nullable))replyHandler {
    replyHandler(nil, nil);
}


- (void)loadResource:(FSResource *)resource
             options:(FSTaskOptions *)options
        replyHandler:(void (^)(FSVolume * _Nullable, NSError * _Nullable))reply
{
    reply(nil, nil);
}

- (void)unloadResource:(FSResource *)resource
               options:(FSTaskOptions *)options
          replyHandler:(void (^)(NSError * _Nullable))reply {
    reply(nil);
}

@end
