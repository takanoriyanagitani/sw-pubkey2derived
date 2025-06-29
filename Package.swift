// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "PubkeyToDerived",
  platforms: [
    .macOS(.v15)
  ],
  products: [
    .library(
      name: "PubkeyToDerived",
      targets: ["PubkeyToDerived"])
  ],
  dependencies: [
    .package(
      url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.4",
    ),
    .package(url: "https://github.com/realm/SwiftLint", from: "0.59.1"),
  ],
  targets: [
    .target(
      name: "PubkeyToDerived"),
    .testTarget(
      name: "PubkeyToDerivedTests",
      dependencies: ["PubkeyToDerived"]
    ),
  ]
)
