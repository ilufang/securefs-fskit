//
//  securefs.swift
//  securefs
//
//  Created by Fang Lu on 11/12/26.
//

import ExtensionFoundation
import Foundation
import FSKit

@main
struct SecureFsExtension : UnaryFileSystemExtension {
    var fileSystem : FSUnaryFileSystem & FSUnaryFileSystemOperations {
		SecureFS()
    }
}
