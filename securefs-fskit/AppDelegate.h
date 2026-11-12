//
//  AppDelegate.h
//  securefs-fskit
//
//  Created by Fang Lu on 11/12/26.
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

/// Opens one mount window per repository (.sfs package opened from Finder, or a folder chosen
/// in the open panel when launched directly) and quits once no window is left.
@interface AppDelegate : NSObject <NSApplicationDelegate>

/// Shows the open panel to choose a repository. Bound to File > Open….
- (IBAction)openDocument:(nullable id)sender;

/// Posts a "mounted" notification, if the user allowed notifications, then calls completion
/// on the main queue.
- (void)postMountNotificationForRepositoryNamed:(NSString *)name
									   mountURL:(NSURL *)mountURL
									 completion:(void (^)(void))completion;

@end

NS_ASSUME_NONNULL_END
