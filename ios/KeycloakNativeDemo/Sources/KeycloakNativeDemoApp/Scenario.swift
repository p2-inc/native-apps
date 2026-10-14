import Foundation

/// The spec/06 §2 scenarios demonstrated in this phase. Each one configures the client and the
/// expected path; the login screen then renders whatever the server offers.
public enum Scenario: String, CaseIterable, Identifiable, Sendable {
  case s1UsernamePasskey
  case s2DiscoverablePasskey
  case s3PasswordTotp
  case s11RegisterSecondPasskey
  case s14BruteForce
  case daveEnrolment

  public var id: String { rawValue }

  public var title: String {
    switch self {
    case .s1UsernamePasskey: "S1 · Username → passkey"
    case .s2DiscoverablePasskey: "S2 · Username-less passkey"
    case .s3PasswordTotp: "S3 · Username → password → TOTP"
    case .s11RegisterSecondPasskey: "S11 · Register a passkey after login"
    case .s14BruteForce: "S14 · Brute force → access_denied"
    case .daveEnrolment: "Enrol a passkey on first login (dave)"
    }
  }

  public var details: String {
    switch self {
    case .s1UsernamePasskey:
      "Client demo-ios. Log in as alice; once alice has a passkey (run S11 first) the primary-factor set is [passkey, password]. Pick the passkey, then TOTP."
    case .s2DiscoverablePasskey:
      "Client demo-ios-passkey: the first challenge set is [passkey (discoverable), username]. Use the passkey without typing a username; user_handle identifies the account."
    case .s3PasswordTotp:
      "Client demo-ios. alice / alice-password, then the 6-digit code from the seeded secret (walkthrough.sh prints it, or any authenticator app with alice-totp-secret-20261014)."
    case .s11RegisterSecondPasskey:
      "After any login, Home → Register passkey: POST /passkey/register/options → platform sheet → /finish. Must happen within 300 s of authenticating, otherwise 403 insufficient_authorization."
    case .s14BruteForce:
      "Client demo-ios, user erin. Submits wrong passwords automatically until Keycloak locks the account (failureFactor 5, or two failures within a second); the flow ends with 403 access_denied."
    case .daveEnrolment:
      "dave / dave-password carries the native-passkey-register required action: after the password the server asks for passkey_registration in-band (challenge_id native-passkey-register). Reset with docker compose down -v."
    }
  }

  /// Which client to use; `nil` keeps the default client.
  public var usesPasskeyClient: Bool { self == .s2DiscoverablePasskey }

  public var prefilledUsername: String? {
    switch self {
    case .s1UsernamePasskey, .s3PasswordTotp, .s11RegisterSecondPasskey: "alice"
    case .s14BruteForce: "erin"
    case .daveEnrolment: "dave"
    case .s2DiscoverablePasskey: nil
    }
  }
}
