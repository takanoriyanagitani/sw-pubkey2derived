// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "PubkeyToDerivedForX25519Cli",
  platforms: [
    .macOS(.v15)
  ],
  dependencies: [
    .package(url: "https://github.com/realm/SwiftLint", from: "0.59.1"),
    .package(path: "../../.."),
  ],
  targets: [
    .executableTarget(
      name: "PubkeyToDerivedForX25519Cli",
      dependencies: [
        .product(name: "PubkeyToDerived", package: "sw-pubkey2derived")
      ],
      swiftSettings: [
        .unsafeFlags(
          ["-cross-module-optimization"],
          .when(configuration: .release),
        )
      ],
    )
  ]
)
