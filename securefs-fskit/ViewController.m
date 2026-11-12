//
//  ViewController.m
//  securefs-fskit
//
//  Created by Fang Lu on 11/12/26.
//

#import "ViewController.h"

#import "AppDelegate.h"

#import <FSKit/FSKit.h>
#import <QuartzCore/QuartzCore.h>

/// The bundle identifier of the embedded FSKit extension.
static NSString *const kExtensionBundleID = @"com.ilufang.securefs-fskit.securefs";

/// Percent-encodes everything but alphanumerics so values survive the extension's
/// comma separated `-o key=value` parsing.
static NSString *encodeOptionValue(NSString *value)
{
	return [value stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.alphanumericCharacterSet];
}

@interface ViewController ()
/// Whether startAccessingSecurityScopedResource succeeded for repositoryURL and must be balanced.
@property (nonatomic) BOOL accessingRepository;
@property (nonatomic) BOOL busy;
@end

@implementation ViewController

- (void)viewDidLoad {
	[super viewDidLoad];
	self.mountButton.keyEquivalent = @"\r";
	self.cancelButton.keyEquivalent = @"\e";
	self.progressIndicator.displayedWhenStopped = NO;
	self.errorLabel.stringValue = @"";
	[self updateUI];
}

- (void)viewWillAppear {
	[super viewWillAppear];
	NSWindow *window = self.view.window;
	window.delegate = self;
	// Each window is tied to a repository chosen at launch; restoring it later makes no sense.
	window.restorable = NO;
	[self updateWindowTitle];
	[window makeFirstResponder:self.passwordField];
}

- (void)dealloc {
	if (_accessingRepository) {
		[_repositoryURL stopAccessingSecurityScopedResource];
	}
}

#pragma mark - State

- (void)setRepositoryURL:(NSURL *)repositoryURL {
	if (self.accessingRepository) {
		[_repositoryURL stopAccessingSecurityScopedResource];
	}
	_repositoryURL = repositoryURL;
	// Keep access while the window is open; FSKit forwards the security scope to the extension.
	self.accessingRepository = [repositoryURL startAccessingSecurityScopedResource];

	NSString *config = [repositoryURL.path stringByAppendingPathComponent:@".securefs.json"];
	if (repositoryURL && ![NSFileManager.defaultManager fileExistsAtPath:config]) {
		[self showError:@"This folder has no .securefs.json and can't be mounted."];
	} else {
		[self showError:nil];
	}
	[self updateWindowTitle];
	[self updateUI];
}

- (void)setBusy:(BOOL)busy {
	_busy = busy;
	[self updateUI];
}

- (void)updateUI {
	BOOL enabled = !self.busy && self.repositoryURL != nil;
	self.passwordField.enabled = enabled;
	self.readOnlyCheckbox.enabled = enabled;
	self.mountButton.enabled = enabled;
	self.mountWithKeyfileButton.enabled = enabled;
	self.cancelButton.enabled = !self.busy;
	if ((self.progressIndicator.hidden = !self.busy)) {
		[self.progressIndicator stopAnimation:nil];
	} else {
		[self.progressIndicator startAnimation:nil];
	}
}

- (void)updateWindowTitle {
	NSWindow *window = self.view.window;
	if (!window || !self.repositoryURL) {
		return;
	}
	window.subtitle = self.repositoryURL.lastPathComponent;
	window.representedURL = self.repositoryURL;
}

- (void)showError:(nullable NSString *)message {
	if (!(self.errorLabel.hidden = !message)) {
		self.errorLabel.stringValue = message;
	}
}

#pragma mark - Actions

- (IBAction)mount:(id)sender {
	if (self.passwordField.stringValue.length == 0) {
		[self showError:@"Enter the password."];
		[self.view.window makeFirstResponder:self.passwordField];
		return;
	}
	[self mountWithKeyfileData:nil];
}

- (IBAction)mountWithKeyfile:(id)sender {
	if (self.busy) {
		return;
	}
	NSOpenPanel *panel = [NSOpenPanel openPanel];
	panel.canChooseDirectories = NO;
	panel.canChooseFiles = YES;
	panel.allowsMultipleSelection = NO;
	panel.message = @"Choose the key file for this repository.";
	panel.prompt = @"Mount";
	[panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse result) {
		if (result != NSModalResponseOK || panel.URL == nil) {
			return;
		}
		NSURL *url = panel.URL;
		BOOL accessing = [url startAccessingSecurityScopedResource];
		NSError *error = nil;
		// The sandboxed extension can't open arbitrary paths, so the contents are passed instead.
		NSData *data = [NSData dataWithContentsOfURL:url options:0 error:&error];
		if (accessing) {
			[url stopAccessingSecurityScopedResource];
		}
		if (!data) {
			[self showError:[NSString stringWithFormat:@"Can't read the key file: %@", error.localizedDescription]];
			return;
		}
		[self mountWithKeyfileData:data];
	}];
}

- (IBAction)cancel:(id)sender {
	if (!self.busy) {
		[self.view.window close];
	}
}

#pragma mark - Mounting

- (NSArray<NSString *> *)mountOptionsWithKeyfileData:(nullable NSData *)keyfileData {
	NSMutableArray<NSString *> *pairs = [NSMutableArray array];
	NSString *password = self.passwordField.stringValue;
	if (password.length > 0) {
		[pairs addObject:[@"password=" stringByAppendingString:encodeOptionValue(password)]];
	}
	if (keyfileData) {
		NSString *base64 = [keyfileData base64EncodedStringWithOptions:0];
		[pairs addObject:[@"keydata=" stringByAppendingString:encodeOptionValue(base64)]];
	}
	if (self.readOnlyCheckbox.state == NSControlStateValueOn) {
		[pairs addObject:@"ro"];
	}
	if (pairs.count == 0) {
		return @[];
	}
	return @[ @"-o", [pairs componentsJoinedByString:@","] ];
}

- (void)mountWithKeyfileData:(nullable NSData *)keyfileData {
	NSURL *url = self.repositoryURL;
	if (!url || self.busy) {
		return;
	}
	BOOL readOnly = self.readOnlyCheckbox.state == NSControlStateValueOn;
	FSPathURLResource *resource = [[FSPathURLResource alloc] initWithURL:url writable:!readOnly];
	NSArray<NSString *> *options = [self mountOptionsWithKeyfileData:keyfileData];

	[self showError:nil];
	self.busy = YES;
	[FSClient.sharedInstance mountSingleVolumeForResource:resource
												 bundleID:kExtensionBundleID
												  options:options
										completionHandler:^(NSURL *mountPath, NSError *error) {
		dispatch_async(dispatch_get_main_queue(), ^{
			if (mountPath) {
				[self didMountAtURL:mountPath];
			} else {
				self.busy = NO;
				[self didFailWithError:error];
			}
		});
	}];
}

- (void)didMountAtURL:(NSURL *)mountPath {
	self.passwordField.stringValue = @"";
	[NSWorkspace.sharedWorkspace activateFileViewerSelectingURLs:@[ mountPath ]];

	// Stay busy (controls disabled) until the window closes.
	AppDelegate *delegate = (AppDelegate *)NSApp.delegate;
	[delegate postMountNotificationForRepositoryNamed:self.repositoryURL.lastPathComponent
											 mountURL:mountPath
										   completion:^{
		[self.view.window close];
	}];
}

- (void)didFailWithError:(nullable NSError *)error {
	[self showError:[self messageForMountError:error]];
	[self shakeWindow];
	NSWindow *window = self.view.window;
	[window makeFirstResponder:self.passwordField];
	[self.passwordField selectText:nil];
}

- (NSString *)messageForMountError:(nullable NSError *)error {
	if ([error.domain isEqualToString:NSPOSIXErrorDomain]) {
		switch (error.code) {
		case EAUTH:
			return @"Wrong password or key file.";
		case ENOTSUP:
			return @"Unsupported repository. Only the securefs lite format (version 4) is supported.";
		case ENOENT:
			return @"The repository's .securefs.json could not be found.";
		default:
			break;
		}
	}
	return [NSString stringWithFormat:@"Mount failed: %@. Make sure the securefs extension is enabled in System Settings.",
			error.localizedDescription ?: @"unknown error"];
}

/// Shakes the window horizontally, like the login window does after a wrong password.
- (void)shakeWindow {
	NSWindow *window = self.view.window;
	if (!window || NSWorkspace.sharedWorkspace.accessibilityDisplayShouldReduceMotion) {
		return;
	}
	NSPoint origin = window.frame.origin;
	static const CGFloat offsets[] = { -10, 10, -8, 8, -5, 5, -2, 2, 0 };
	CGMutablePathRef path = CGPathCreateMutable();
	CGPathMoveToPoint(path, NULL, origin.x, origin.y);
	for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		CGPathAddLineToPoint(path, NULL, origin.x + offsets[i], origin.y);
	}
	CAKeyframeAnimation *animation = [CAKeyframeAnimation animation];
	animation.path = path;
	animation.duration = 0.4;
	CGPathRelease(path);
	// NSWindow animates frameOrigin through its animator proxy using this animation.
	window.animations = @{ @"frameOrigin": animation };
	[window.animator setFrameOrigin:origin];
}

#pragma mark - NSWindowDelegate

- (BOOL)windowShouldClose:(NSWindow *)sender {
	// Closing mid-mount would leave the result with nowhere to go.
	return !self.busy;
}

@end
