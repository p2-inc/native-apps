import Foundation
@testable import KeycloakNativeCore

/// Builds an SDK instance wired to a transport, an in-memory store and a scripted passkey platform.
struct Harness {
  let sdk: KeycloakNative
  let transport: any Transport
  let store: InMemorySecureStore
  let passkeys: MockPasskeyPlatform
  let observer: CapturingObserver
  let logger: CapturingLogger

  init(issuer: URL, clientId: String, transport: any Transport, dpop: DPoPMode = .software, allowRpIdMismatch: Bool = false) {
    let store = InMemorySecureStore()
    let passkeys = MockPasskeyPlatform()
    let observer = CapturingObserver()
    let logger = CapturingLogger()
    var options = KeycloakNative.Options()
    options.transport = transport
    options.secureStore = store
    options.passkeyPlatform = passkeys
    options.flowObserver = observer
    options.logger = logger
    options.dpop = dpop
    options.allowRpIdMismatch = allowRpIdMismatch
    self.sdk = KeycloakNative.configure(issuer: issuer, clientId: clientId, options: options)
    self.transport = transport
    self.store = store
    self.passkeys = passkeys
    self.observer = observer
    self.logger = logger
  }

  /// Metadata exchange (always the first request of a flow) followed by the scenario's exchanges.
  static func replay(_ names: [String], clientId: String, metadataFrom: String = "NativeAuthIT.metadataIsServedUnderRealmNativeAuthPath", range: ClosedRange<Int>? = nil) throws -> (Harness, MockTransport, [Transcript]) {
    let metadata = try Transcript.load(metadataFrom)
    let transcripts = try names.map(Transcript.load)
    var exchanges = [metadata.exchange(1)]
    if let range, transcripts.count == 1 {
      exchanges += transcripts[0].exchanges(range)
    } else {
      exchanges += transcripts.flatMap(\.exchanges)
    }
    let transport = MockTransport(exchanges)
    let harness = Harness(issuer: metadata.issuer, clientId: clientId, transport: transport)
    return (harness, transport, transcripts)
  }
}

extension Array where Element == Challenge {
  func first(_ type: ChallengeType) -> Challenge? {
    first { $0.type == type }
  }

  var types: [String] { map(\.type.wire) }
}
