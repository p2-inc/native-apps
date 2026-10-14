import Foundation

/// The §4.3 wire fields of a WebAuthn assertion, all base64url without padding.
public struct PasskeyAssertion: Sendable, Equatable {
  public let credentialId: String
  public let clientDataJSON: String
  public let authenticatorData: String
  public let signature: String
  /// Present for resident credentials; names the user in discoverable logins.
  public let userHandle: String?

  public init(credentialId: String, clientDataJSON: String, authenticatorData: String, signature: String, userHandle: String?) {
    self.credentialId = credentialId
    self.clientDataJSON = clientDataJSON
    self.authenticatorData = authenticatorData
    self.signature = signature
    self.userHandle = userHandle
  }

  public init(credentialId: Data, clientDataJSON: Data, authenticatorData: Data, signature: Data, userHandle: Data?) {
    self.init(
      credentialId: Base64URL.encode(credentialId),
      clientDataJSON: Base64URL.encode(clientDataJSON),
      authenticatorData: Base64URL.encode(authenticatorData),
      signature: Base64URL.encode(signature),
      userHandle: userHandle.map(Base64URL.encode))
  }

  public var formFields: [(name: String, value: String)] {
    var fields: [(name: String, value: String)] = [
      ("credential_id", credentialId),
      ("client_data_json", clientDataJSON),
      ("authenticator_data", authenticatorData),
      ("signature", signature),
    ]
    if let userHandle { fields.append(("user_handle", userHandle)) }
    return fields
  }
}

/// The §4.4 / §6 wire fields of a WebAuthn registration (attestation), base64url without padding.
public struct PasskeyAttestation: Sendable, Equatable {
  public let credentialId: String
  public let clientDataJSON: String
  public let attestationObject: String
  /// e.g. `["internal", "hybrid"]` for platform passkeys.
  public let transports: [String]

  public init(credentialId: String, clientDataJSON: String, attestationObject: String, transports: [String]) {
    self.credentialId = credentialId
    self.clientDataJSON = clientDataJSON
    self.attestationObject = attestationObject
    self.transports = transports
  }

  public init(credentialId: Data, clientDataJSON: Data, attestationObject: Data, transports: [String]) {
    self.init(
      credentialId: Base64URL.encode(credentialId),
      clientDataJSON: Base64URL.encode(clientDataJSON),
      attestationObject: Base64URL.encode(attestationObject),
      transports: transports)
  }

  public var formFields: [(name: String, value: String)] {
    [
      ("credential_id", credentialId),
      ("client_data_json", clientDataJSON),
      ("attestation_object", attestationObject),
      ("transports", transports.joined(separator: ",")),
    ]
  }

  /// The §6 `finish` JSON body (without `registration_id` and `label`).
  public var jsonFields: [String: JSONValue] {
    [
      "credential_id": .string(credentialId),
      "client_data_json": .string(clientDataJSON),
      "attestation_object": .string(attestationObject),
      "transports": .array(transports.map(JSONValue.string)),
    ]
  }
}

/// Result of a §6 registration.
public struct RegisteredPasskey: Sendable, Equatable {
  public let credentialId: String
  public let label: String?
}
