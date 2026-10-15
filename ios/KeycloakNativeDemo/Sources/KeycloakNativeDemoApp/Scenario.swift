import Foundation

/// The spec/06 §2 scenarios demonstrated by the app. Each one configures the client and the
/// expected path; the login screen then renders whatever the server offers.
public enum Scenario: String, CaseIterable, Identifiable, Sendable {
  case s1UsernamePasskey
  case s2DiscoverablePasskey
  case s3PasswordTotp
  case s4EmailOtp
  case s5DefaultUI
  case s6StepUp
  case s7RedirectToWeb
  case s8RefreshReauth
  case s9PushEnrolAndApprove
  case s10PushNativeLogin
  case s11RegisterSecondPasskey
  case s12PushMaintenance
  case s13CustomPresenter
  case s14BruteForce
  case daveEnrolment
  case carolUpdatePassword
  case graceVerifyEmail
  case hankTerms
  case ivyRecoveryCode
  case judyPushEnrol

  public var id: String { rawValue }

  public var title: String {
    switch self {
    case .s1UsernamePasskey: "S1 · Username → passkey"
    case .s2DiscoverablePasskey: "S2 · Username-less passkey"
    case .s3PasswordTotp: "S3 · Username → password → TOTP"
    case .s4EmailOtp: "S4 · Email one-time code with resend"
    case .s5DefaultUI: "S5 · Default UI with factor chooser"
    case .s6StepUp: "S6 · Step-up for a protected action"
    case .s7RedirectToWeb: "S7 · Redirect to web (frank)"
    case .s8RefreshReauth: "S8 · Refresh forces re-authentication"
    case .s9PushEnrolAndApprove: "S9 · Enrol for push, approve a browser login"
    case .s10PushNativeLogin: "S10 · Push as the native second factor"
    case .s11RegisterSecondPasskey: "S11 · Register a passkey after login"
    case .s12PushMaintenance: "S12 · Push device: APNs token, key rotation, lockout"
    case .s13CustomPresenter: "S13 · Default UI with a custom TOTP screen"
    case .s14BruteForce: "S14 · Brute force → access_denied"
    case .daveEnrolment: "Enrol a passkey on first login (dave)"
    case .carolUpdatePassword: "Update password in-band (carol)"
    case .graceVerifyEmail: "Verify email with a code (grace)"
    case .hankTerms: "Accept terms and conditions (hank)"
    case .ivyRecoveryCode: "Recovery code instead of TOTP (ivy)"
    case .judyPushEnrol: "Enrol for push mid-flow (judy)"
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
    case .s4EmailOtp:
      "Client demo-ios-otp. bob / bob-password gets an email code as the only second factor (sent at once); alice gets [totp, otp] and the code is only sent when she asks for it. Codes land in mailpit (http://localhost:8025). Resend has a 10 s cooldown."
    case .s5DefaultUI:
      "Client demo-ios-otp with the KeycloakNativeUI product: NativeLoginView drives the whole flow with the default screens and the “Try another way” chooser (alice sees TOTP vs email code)."
    case .s6StepUp:
      "Client demo-ios-stepup. Log in (password only = acr 1), then Home → Transfer: the demo API answers 401 insufficient_user_authentication acr_values=2; the app steps up with the stored auth_session (only TOTP is asked), retries and succeeds with acr 2."
    case .s7RedirectToWeb:
      "Client demo-ios. frank / frank-password has a pending Update Profile action with no native variant: the server answers redirect_to_web with a PAR request_uri; Safari completes the login and the code comes back to the app (demoapp://auth/callback)."
    case .s8RefreshReauth:
      "After any login: Home → “End session on the server” (revokes the refresh token), then “Refresh tokens”: the SDK reports reauthentication_required and the app starts a new login."
    case .s9PushEnrolAndApprove:
      "Log in as alice (password + TOTP), then Home → “Enrol this device for push”: POST /native-auth/push/enroll/start with the DPoP-bound token, then /push-mfa/enroll/complete with a device JWT signed by the DPoP key (spec/03 §7.1). Then sign in as alice in a browser (http://localhost:8089/realms/demo/account): the realm's browser flow asks the phone — Home → “Sign-in requests” lists it (pull to refresh; the simulator gets no APNs), Approve finishes the browser login."
    case .s10PushNativeLogin:
      "With this device enrolled (S9): a native login of alice offers [totp, push]. “Send request” creates the push challenge and shows a number; Home → “Sign-in requests” shows three numbers — pick the matching one; back on Login the app polls (action=poll) and finishes."
    case .s12PushMaintenance:
      "Home → push section: “Simulate APNs token” (PUT /device/push-provider; a real device registers its token through the app delegate), “Rotate device key” (PUT /device/rotate-key with the new DPoP key; the stored tokens were bound to the old key, so sign in again), “Lock out” (POST /login/lockout disables the account until an admin re-enables it: docker compose down -v, or the admin console)."
    case .s11RegisterSecondPasskey:
      "After any login, Home → Register passkey: POST /passkey/register/options → platform sheet → /finish. After 300 s the server answers 403 insufficient_authorization with an auth_session: the app steps up with max_age and retries."
    case .s13CustomPresenter:
      "Same as S5 but the TOTP screen is replaced through challengePresenter(for: .totp) — the SDK's screens are replaceable one by one."
    case .s14BruteForce:
      "Client demo-ios, user erin. Submits wrong passwords automatically until Keycloak locks the account (failureFactor 5, or two failures within a second); the flow ends with 403 access_denied."
    case .daveEnrolment:
      "dave / dave-password carries the native-passkey-register required action: after the password the server asks for passkey_registration in-band (challenge_id native-passkey-register). Reset with docker compose down -v."
    case .carolUpdatePassword:
      "carol / carol-password has Keycloak's UPDATE_PASSWORD pending; native-update-password serves it in-band (spec/03 §4.12): choose a new password (use carol-password again to keep the demo repeatable). The realm's password policy is shown as hints; a rejected password comes back as invalid_password."
    case .graceVerifyEmail:
      "grace / grace-password has VERIFY_EMAIL pending; native-verify-email sends a 6-digit code to g***@example.com (mailpit, http://localhost:8025) as soon as the challenge appears (spec/03 §4.13); resend has a 30 s cooldown."
    case .hankTerms:
      "hank / hank-password has TERMS_AND_CONDITIONS pending; native-terms shows the realm's terms text and link (spec/03 §4.14). Accept continues to the tokens; Decline ends the login with access_denied."
    case .judyPushEnrol:
      "judy / judy-password carries ba-itsys' push-mfa-register required action; native-push-enroll serves it in-band (spec/03 §4.15): after the password the app enrols this device with its DPoP key (token=<device JWT>) and the login completes. The next login of judy asks for push (sent at once, single option). Reset with docker compose down -v."
    case .ivyRecoveryCode:
      "ivy / ivy-password has TOTP and three recovery codes: the second factor offers [totp, recovery_code] (spec/03 §4.8). Codes IVY1-IVY1-IVY1, IVY2-IVY2-IVY2, IVY3-IVY3-IVY3 are single use and consumed in order; after the last one Keycloak requires new codes (redirect to web). Reset with docker compose down -v."
    }
  }

  /// Which SDK client the scenario uses.
  public enum ClientRole: Sendable { case standard, passkey, stepUp, otp }

  public var client: ClientRole {
    switch self {
    case .s2DiscoverablePasskey: .passkey
    case .s4EmailOtp, .s5DefaultUI, .s13CustomPresenter: .otp
    case .s6StepUp: .stepUp
    default: .standard
    }
  }

  /// Kept for the Phase 1b call sites.
  public var usesPasskeyClient: Bool { client == .passkey }

  /// Scenarios rendered by `NativeLoginView` (KeycloakNativeUI) instead of the hand-rolled screens.
  public var usesDefaultUI: Bool { self == .s5DefaultUI || self == .s13CustomPresenter }

  public var prefilledUsername: String? {
    switch self {
    case .s1UsernamePasskey, .s3PasswordTotp, .s11RegisterSecondPasskey, .s6StepUp, .s8RefreshReauth, .s5DefaultUI, .s13CustomPresenter, .s9PushEnrolAndApprove, .s10PushNativeLogin, .s12PushMaintenance: "alice"
    case .s4EmailOtp: "bob"
    case .s7RedirectToWeb: "frank"
    case .s14BruteForce: "erin"
    case .daveEnrolment: "dave"
    case .carolUpdatePassword: "carol"
    case .graceVerifyEmail: "grace"
    case .hankTerms: "hank"
    case .ivyRecoveryCode: "ivy"
    case .judyPushEnrol: "judy"
    case .s2DiscoverablePasskey: nil
    }
  }
}
