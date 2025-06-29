import struct CryptoKit.SHA256
import struct CryptoKit.SymmetricKey
import struct Foundation.Data
import class Foundation.FileHandle
import class Foundation.ProcessInfo
import struct PubkeyToDerived.Info
import typealias PubkeyToDerived.PrivateKey4x25519
import typealias PubkeyToDerived.Pubkey4x25519
import struct PubkeyToDerived.PublicInfo
import struct PubkeyToDerived.Salt
import func PubkeyToDerived.key2digest
import func PubkeyToDerived.newKey4x25519
import func PubkeyToDerived.pubkey2der
import func PubkeyToDerived.pubkey2derived4x25519
import func PubkeyToDerived.pubkey2pem
import func PubkeyToDerived.raw2pubkey4x25519

enum Key2derivedErr: Error {
  case invalidArgument(String)
}

struct Combined {
  public let pubInfo: PublicInfo
  private let myKey: PrivateKey4x25519

  public static func fromSecret(
    _ myKey: PrivateKey4x25519,
    pubInfo: PublicInfo,
  ) -> Self {
    Self(pubInfo: pubInfo, myKey: myKey)
  }

  public func publicKey() -> Pubkey4x25519 { self.pubInfo.pubkey }
  public func myPublicKey() -> Pubkey4x25519 { self.myKey.publicKey }

  public func sharedInfo() -> Info { self.pubInfo.info }
  public func salt() -> Salt { self.pubInfo.salt }

  public func toSymmetricKey() -> Result<SymmetricKey, Error> {
    self.pubInfo.toSymmetricKey(secretKey: self.myKey)
  }

  public func myPubkeyToDer() -> Data { pubkey2der(self.myPublicKey()) }
  public func myPubkeyToPem() -> String { pubkey2pem(self.myPublicKey()) }
}

extension Combined: CustomStringConvertible {
  var description: String {
    let myPubKeyPem: String = self.myPubkeyToPem()
    let sharedInfo: String = self.sharedInfo().toBase64()
    let salt: String = self.salt().toBase64()
    return """
      Shared Info(base64): \( sharedInfo )
      Salt(base64): \( salt )
      My Public Key(Pem):
      \( myPubKeyPem )
      """
  }
}

func printCombined(_ combined: Combined) -> IO<Void> {
  return {
    print(combined)
    let rsym: Result<SymmetricKey, _> = combined.toSymmetricKey()
    return rsym.map {
      let secret: SymmetricKey = $0
      let digest: SHA256.Digest = key2digest(secretKey: secret)
      print("\( digest )")
      return ()
    }
  }
}

typealias IO<T> = () -> Result<T, Error>

func envValByKey(_ key: String) -> IO<String> {
  let envVars: [String: String] = ProcessInfo.processInfo.environment
  return {
    let oval: String? = envVars[key]
    guard let val = oval else {
      return .failure(Key2derivedErr.invalidArgument("undefined var \( key )"))
    }
    return .success(val)
  }
}

func limit2filename2data(limit: Int = 32) -> (String) -> IO<Data> {
  return {
    let filename: String = $0
    return {
      let ofile: FileHandle? = FileHandle(forReadingAtPath: filename)
      guard let file = ofile else {
        return .failure(
          Key2derivedErr.invalidArgument(
            "unable to open: \( filename )",
          ),
        )
      }
      defer {
        try? file.close()
      }
      let rdat: Result<Data, _> = Result(catching: {
        try file.read(upToCount: limit) ?? Data()
      })
      return rdat
    }
  }
}

func bind<T, U>(
  _ io: @escaping IO<T>,
  _ mapper: @escaping (T) -> IO<U>,
) -> IO<U> {
  return {
    let rt: Result<T, _> = io()
    return rt.flatMap {
      let t: T = $0
      return mapper(t)()
    }
  }
}

func lift<T, U>(
  _ pure: @escaping (T) -> Result<U, Error>,
) -> (T) -> IO<U> {
  return {
    let t: T = $0
    return {
      return pure(t)
    }
  }
}

func printDigest(_ digest: SHA256.Digest) -> IO<Void> {
  return {
    print("\( digest )")
    return .success(())
  }
}

@main
struct PubkeyToDerivedForX25519Cli {
  static func main() {
    let ipubKeyLocation: IO<String> = envValByKey("ENV_RAW_PUBKEY_LOCATION")
    let ipubKeyRaw: IO<Data> = bind(
      ipubKeyLocation,
      limit2filename2data(),
    )
    let ipubkey: IO<Pubkey4x25519> = bind(
      ipubKeyRaw,
      lift(raw2pubkey4x25519),
    )

    let key: PrivateKey4x25519 = newKey4x25519()

    let sharedInfo: Info = .newInfo(
      fqdn: Data("com.github.takanoriyanagitani".utf8),
      codeName: Data("pubkey2derived".utf8),
      useCase: Data("alice-bob".utf8),
    )

    // use this for production
    // let isaltData: IO<Data> = limit2filename2data()("/dev/urandom")

    // for test only
    let isaltData: IO<Data> = limit2filename2data()("./sample.d/salt4test.dat")

    let isalt: IO<Salt> = bind(
      isaltData,
      lift(Salt.fromRaw),
    )

    let ipubInfo: IO<PublicInfo> = bind(
      isalt,
      {
        let salt: Salt = $0
        return bind(
          ipubkey,
          lift {
            .success(
              .fromSalt(
                salt,
                info: sharedInfo,
                pubkey: $0
              ))
          },
        )
      },
    )

    let icombined: IO<Combined> = bind(
      ipubInfo,
      lift {
        .success(
          .fromSecret(
            key,
            pubInfo: $0,
          ))
      },
    )

    let iprint: IO<Void> = bind(icombined, printCombined)

    do {
      try iprint().get()
    } catch {
      print("error: \( error )")
    }

  }
}
