import enum CryptoKit.Curve25519
import struct CryptoKit.HKDF
import struct CryptoKit.SHA256
import struct CryptoKit.SharedSecret
import struct CryptoKit.SymmetricKey
import struct Foundation.Data

public enum KeyToDerivedErr: Error {
  case invalidArgument(String)
}

public typealias KeyAgreement4x25519 = Curve25519.KeyAgreement

public typealias Pubkey4x25519 = KeyAgreement4x25519.PublicKey
public typealias PrivateKey4x25519 = KeyAgreement4x25519.PrivateKey

public struct Salt {
  private let salt: Data

  public func raw() -> Data { self.salt }

  public static func fromRaw(_ raw: Data) -> Result<Self, Error> {
    guard 32 <= raw.count else {
      return .failure(KeyToDerivedErr.invalidArgument("too short salt"))
    }
    return .success(Self(salt: raw))
  }

  public func toBase64() -> String { self.salt.base64EncodedString() }
}

public struct Info {
  public let info: Data

  public static func newInfo(
    fqdn: Data,
    codeName: Data,
    useCase: Data,
  ) -> Self {
    let sz: Int = fqdn.count + codeName.count + useCase.count
    var info: Data = Data(capacity: sz)
    info.append(fqdn)
    info.append(codeName)
    info.append(useCase)
    return Self(info: info)
  }

  public func toBase64() -> String { self.info.base64EncodedString() }
}

public struct KeyGenerator4x25519 {
  public let info: Info

  private let key: SharedSecret

  public func deriveKey(salt: Salt) -> SymmetricKey {
    self.key.hkdfDerivedSymmetricKey(
      using: SHA256.self,
      salt: salt.raw(),
      sharedInfo: info.info,
      outputByteCount: 32,
    )
  }

  public static func fromSecret(_ shared: SharedSecret, info: Info) -> Self {
    Self(info: info, key: shared)
  }
}

public func pubkey2derived4x25519(
  _ pubkey: Pubkey4x25519,
  key: PrivateKey4x25519,
  sharedInfo: Info,
  salt: Salt,
) -> Result<SymmetricKey, Error> {
  let rshared: Result<SharedSecret, Error> = Result(catching: {
    try key.sharedSecretFromKeyAgreement(with: pubkey)
  })
  return rshared.map {
    let shared: SharedSecret = $0
    let keygen: KeyGenerator4x25519 = .fromSecret(
      shared,
      info: sharedInfo,
    )
    return keygen.deriveKey(salt: salt)
  }
}

/// Converts the raw data(public key, 32-bytes) to a Public Key.
public func raw2pubkey4x25519(_ raw: Data) -> Result<Pubkey4x25519, Error> {
  Result(catching: { try Pubkey4x25519(rawRepresentation: raw) })
}

public func secret2key4x25519(secret: Data) -> Result<PrivateKey4x25519, Error> {
  Result(catching: { try PrivateKey4x25519(rawRepresentation: secret) })
}

public func newKey4x25519() -> PrivateKey4x25519 { PrivateKey4x25519() }

public struct PublicInfo {
  public let pubkey: Pubkey4x25519
  public let salt: Salt
  public let info: Info

  public static func fromSalt(
    _ salt: Salt,
    info: Info,
    pubkey: Pubkey4x25519,
  ) -> Self {
    Self(pubkey: pubkey, salt: salt, info: info)
  }

  public func toSymmetricKey(
    secretKey: PrivateKey4x25519,
  ) -> Result<SymmetricKey, Error> {
    pubkey2derived4x25519(
      self.pubkey,
      key: secretKey,
      sharedInfo: self.info,
      salt: self.salt,
    )
  }
}

public func key2digest(secretKey: SymmetricKey) -> SHA256.Digest {
  secretKey.withUnsafeBytes {
    let raw: UnsafeRawBufferPointer = $0
    var hash: SHA256 = SHA256()
    hash.update(bufferPointer: raw)
    return hash.finalize()
  }
}

public let derPrefix4x25519: Data = Data([
  0x30, 0x2a,
  0x30, 0x05,
  0x06, 0x03, 0x2b, 0x65, 0x6e,
  0x03, 0x21, 0x00,
])

public func pubkey2der(_ pubkey: Pubkey4x25519) -> Data {
  var der: Data = Data(capacity: 44)
  der.append(derPrefix4x25519)
  der.append(pubkey.rawRepresentation)
  return der
}

public let pemHeader: String = "-----BEGIN PUBLIC KEY-----"
public let pemFooter: String = "-----END PUBLIC KEY-----"

public func pubkey2pem(_ pubkey: Pubkey4x25519) -> String {
  pemHeader + "\n" + pubkey2der(pubkey).base64EncodedString() + "\n" + pemFooter
}
