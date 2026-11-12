//
//  AppDelegate.m
//  securefs-fskit
//
//  Created by Fang Lu on 11/12/26.
//

#import "AppDelegate.h"

#import "ViewController.h"

#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <UserNotifications/UserNotifications.h>

/// The exported type of .sfs repository packages, declared in Info.plist.
static NSString *const kRepositoryTypeIdentifier = @"com.ilufang.securefs-fskit.repository";
/// Storyboard identifier of the mount window controller.
static NSStoryboardSceneIdentifier const kMountWindowIdentifier = @"MountWindow";
/// Notification userInfo key holding the mount point path.
static NSString *const kMountPathUserInfoKey = @"mountPath";

@interface AppDelegate () <UNUserNotificationCenterDelegate>
@property (nonatomic) NSMutableArray<NSWindowController *> *mountWindows;
@property (nonatomic) BOOL pickerVisible;
@end

@implementation AppDelegate

- (instancetype)init {
	self = [super init];
	if (self) {
		_mountWindows = [NSMutableArray array];
	}
	return self;
}

#pragma mark - Lifecycle

- (void)applicationWillFinishLaunching:(NSNotification *)notification {
	UNUserNotificationCenter.currentNotificationCenter.delegate = self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
	// Ask up front so the answer is known by the time the first mount succeeds.
	[UNUserNotificationCenter.currentNotificationCenter
		requestAuthorizationWithOptions:UNAuthorizationOptionAlert
					  completionHandler:^(BOOL granted, NSError *error) {}];

	if (aNotification.userInfo[NSApplicationLaunchUserNotificationKey]) {
		// Launched by clicking a "mounted" notification: the response handler opens the volume
		// and quits. Don't show the picker; just make sure the process doesn't linger.
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
			[self terminateIfIdle];
		});
		return;
	}

	// Packages opened from Finder arrive through -application:openURLs: before this point.
	// Defer the check one turn so a late delivery still wins over the picker.
	dispatch_async(dispatch_get_main_queue(), ^{
		if (self.mountWindows.count == 0) {
			[self showRepositoryPicker];
		}
	});
}

- (void)application:(NSApplication *)application openURLs:(NSArray<NSURL *> *)urls {
	for (NSURL *url in urls) {
		[self openRepositoryAtURL:url];
	}
}

- (BOOL)applicationShouldOpenUntitledFile:(NSApplication *)sender {
	// There are no untitled documents; launching without a package shows the picker instead.
	return NO;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
	if (!flag && self.mountWindows.count == 0) {
		[self showRepositoryPicker];
	}
	return NO;
}

- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app {
	return YES;
}

#pragma mark - Windows

- (IBAction)openDocument:(id)sender {
	[self showRepositoryPicker];
}

- (void)showRepositoryPicker {
	if (self.pickerVisible) {
		return;
	}
	NSOpenPanel *panel = [NSOpenPanel openPanel];
	// .sfs packages count as files to the panel; plain folders as directories.
	panel.canChooseFiles = YES;
	panel.canChooseDirectories = YES;
	panel.allowsMultipleSelection = NO;
	UTType *repositoryType = [UTType typeWithIdentifier:kRepositoryTypeIdentifier];
	panel.allowedContentTypes = repositoryType ? @[ repositoryType, UTTypeFolder ] : @[ UTTypeFolder ];
	panel.message = @"Choose a securefs repository (the folder containing .securefs.json).";
	panel.prompt = @"Choose";

	self.pickerVisible = YES;
	[NSApp activate];
	[panel beginWithCompletionHandler:^(NSModalResponse result) {
		self.pickerVisible = NO;
		if (result == NSModalResponseOK && panel.URL) {
			[self openRepositoryAtURL:panel.URL];
		}
		[self terminateIfIdle];
	}];
}

- (void)openRepositoryAtURL:(NSURL *)url {
	NSString *path = url.URLByStandardizingPath.path;
	for (NSWindowController *controller in self.mountWindows) {
		ViewController *viewController = (ViewController *)controller.contentViewController;
		if ([viewController.repositoryURL.URLByStandardizingPath.path isEqualToString:path]) {
			[controller showWindow:nil];
			[NSApp activate];
			return;
		}
	}

	NSStoryboard *storyboard = [NSStoryboard storyboardWithName:@"Main" bundle:nil];
	NSWindowController *controller = [storyboard instantiateControllerWithIdentifier:kMountWindowIdentifier];
	ViewController *viewController = (ViewController *)controller.contentViewController;
	viewController.repositoryURL = url;

	[self.mountWindows addObject:controller];
	[NSNotificationCenter.defaultCenter addObserver:self
										   selector:@selector(mountWindowWillClose:)
											   name:NSWindowWillCloseNotification
											 object:controller.window];
	[controller.window center];
	[controller showWindow:nil];
	[NSApp activate];
}

- (void)mountWindowWillClose:(NSNotification *)notification {
	NSWindow *window = notification.object;
	[NSNotificationCenter.defaultCenter removeObserver:self name:NSWindowWillCloseNotification object:window];
	NSUInteger index = [self.mountWindows indexOfObjectPassingTest:^BOOL(NSWindowController *controller, NSUInteger idx, BOOL *stop) {
		return controller.window == window;
	}];
	if (index != NSNotFound) {
		[self.mountWindows removeObjectAtIndex:index];
	}
	// Let the close finish before deciding to quit.
	dispatch_async(dispatch_get_main_queue(), ^{
		[self terminateIfIdle];
	});
}

/// Quits once there is neither a mount window nor the repository picker on screen.
- (void)terminateIfIdle {
	if (self.mountWindows.count == 0 && !self.pickerVisible) {
		[NSApp terminate:nil];
	}
}

#pragma mark - Notifications

- (void)postMountNotificationForRepositoryNamed:(NSString *)name
									   mountURL:(NSURL *)mountURL
									 completion:(void (^)(void))completion {
	UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
	content.title = [NSString stringWithFormat:@"Mounted “%@”", name];
	NSString *path = mountURL.path ?: @"";
	content.body = path;
	content.userInfo = @{ kMountPathUserInfoKey: path };
	UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:NSUUID.UUID.UUIDString
																		  content:content
																		  trigger:nil];
	// Fails quietly when notifications aren't allowed; the window closes either way.
	[UNUserNotificationCenter.currentNotificationCenter addNotificationRequest:request
														 withCompletionHandler:^(NSError *error) {
		dispatch_async(dispatch_get_main_queue(), completion);
	}];
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
	   willPresentNotification:(UNNotification *)notification
		 withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
	// Show the banner even if the app is still frontmost when it's posted.
	completionHandler(UNNotificationPresentationOptionBanner);
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
	didReceiveNotificationResponse:(UNNotificationResponse *)response
			 withCompletionHandler:(void (^)(void))completionHandler {
	// Clicking the notification always activates the app; the best we can do is open the
	// volume in Finder and get out of the way again.
	NSString *path = response.notification.request.content.userInfo[kMountPathUserInfoKey];
	if ([path isKindOfClass:NSString.class]) {
		NSURL *url = [NSURL fileURLWithPath:path isDirectory:YES];
		[NSWorkspace.sharedWorkspace activateFileViewerSelectingURLs:@[ url ]];
	}
	completionHandler();
	dispatch_async(dispatch_get_main_queue(), ^{
		[self terminateIfIdle];
	});
}

@end
