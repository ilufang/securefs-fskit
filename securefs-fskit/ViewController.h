//
//  ViewController.h
//  securefs-fskit
//
//  Created by Fang Lu on 11/12/26.
//

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

/// Prompts for the credentials of one securefs repository and mounts it through the FSKit extension.
///
/// The app delegate instantiates one window per repository from the storyboard window controller
/// with identifier "MountWindow", then sets repositoryURL. The window closes itself after a
/// successful mount.
///
/// Storyboard connections:
/// - passwordField: NSSecureTextField for the repository password.
/// - readOnlyCheckbox: NSButton (checkbox) to mount read-only.
/// - mountButton: NSButton bound to -mount: (mount with password).
/// - mountWithKeyfileButton: NSButton bound to -mountWithKeyfile:.
/// - cancelButton: NSButton bound to -cancel:.
/// - errorLabel: NSTextField (label) for error messages.
/// - progressIndicator: NSProgressIndicator (spinning style) shown while mounting.
@interface ViewController : NSViewController <NSWindowDelegate>

/// The repository directory (containing .securefs.json) this window mounts.
@property (nonatomic, nullable) NSURL *repositoryURL;

@property (weak) IBOutlet NSSecureTextField *passwordField;
@property (weak) IBOutlet NSButton *readOnlyCheckbox;
@property (weak) IBOutlet NSButton *mountButton;
@property (weak) IBOutlet NSButton *mountWithKeyfileButton;
@property (weak) IBOutlet NSButton *cancelButton;
@property (weak) IBOutlet NSTextField *errorLabel;
@property (weak) IBOutlet NSProgressIndicator *progressIndicator;

/// Mounts the repository using the entered password.
- (IBAction)mount:(id)sender;
/// Asks for a key file, then mounts the repository using it (plus the password, if entered).
- (IBAction)mountWithKeyfile:(id)sender;
/// Closes the window without mounting.
- (IBAction)cancel:(id)sender;

@end

NS_ASSUME_NONNULL_END
