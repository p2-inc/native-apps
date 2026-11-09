// The platform channel between the Dart API and the native SDKs (spec/18 §4). Generate with
// `dart run pigeon --input pigeons/messages.dart` from flutter/keycloak_native; the outputs are
// committed. The protocol stays in the native SDKs: Dart sends typed answers and receives the
// descriptors the native state machine parsed, with each `params` object as JSON text that the Dart
// models read for display. Tokens other than the access and ID token never cross the channel.
import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    dartOptions: DartOptions(),
    kotlinOut: 'android/src/main/kotlin/io/phasetwo/keycloak/nativeauth/flutter/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'io.phasetwo.keycloak.nativeauth.flutter'),
    swiftOut: 'ios/keycloak_native/Sources/keycloak_native/Messages.g.swift',
    swiftOptions: SwiftOptions(),
    dartPackageName: 'keycloak_native',
  ),
)
/// `KeycloakNative.Options.dpop` of the native SDKs.
enum DPoPModeMessage { automatic, hardware, software, disabled }

class ConfigureMessage {
  ConfigureMessage({
    required this.issuer,
    required this.clientId,
    required this.dpop,
    required this.allowRpIdMismatch,
    required this.ephemeralWebSession,
  });

  String issuer;
  String clientId;
  DPoPModeMessage dpop;
  bool allowRpIdMismatch;

  /// iOS `prefersEphemeralWebBrowserSession`, Android `AuthTabWebPresenter(ephemeral = …)`.
  bool ephemeralWebSession;

  /// Android `KeystoreSecureStore` namespace; defaults to the client id. iOS uses the Keychain with
  /// the SDK's default service.
  String? storageNamespace;
  int? metadataCacheTtlSeconds;

  /// Send the SDK's redacted request/response entries to `KeycloakNativeFlutterApi.onFlowLog`.
  bool? observeFlow;
}

class LoginParametersMessage {
  LoginParametersMessage({required this.additionalParameters, required this.continuationParameters});

  String? scope;
  String? acrValues;
  String? loginHint;
  String? prompt;
  int? maxAge;
  String? nonce;
  String? uiLocales;
  String? deviceName;
  String? deviceId;
  Map<String, String> additionalParameters;
  Map<String, String> continuationParameters;
}

/// A challenge descriptor (spec/03 §3.3) as the native SDK parsed it.
class ChallengeMessage {
  ChallengeMessage({
    required this.id,
    required this.type,
    required this.required,
    required this.skippable,
    required this.paramsJson,
  });

  String id;

  /// The wire value (`username`, `password`, …), also for types the native SDK does not know.
  String type;
  String? label;
  bool required;
  String? errorCode;
  String? errorMessage;

  /// `retry` present; `retryRemaining` may still be null.
  bool? hasRetry;
  int? retryRemaining;
  bool skippable;

  /// `params` as JSON text (an empty object when absent).
  String paramsJson;
}

enum FlowStepKind { challenges, authorized, redirectToWeb }

class CredentialsMessage {
  CredentialsMessage({
    required this.handle,
    required this.accessToken,
    required this.tokenType,
    required this.expiresAtMillis,
    required this.issuedAtMillis,
    required this.hasRefreshToken,
  });

  /// Names the native `Credentials` object for `storeCredentials`; the refresh token and the
  /// post-login `auth_session` stay on the native side.
  String handle;
  String accessToken;
  String tokenType;
  String? idToken;
  String? scope;
  int expiresAtMillis;

  /// Absent when the server sent no `refresh_expires_in`; a far-future value for offline tokens.
  int? refreshExpiresAtMillis;
  int issuedAtMillis;
  bool hasRefreshToken;
}

class RedirectToWebMessage {
  RedirectToWebMessage({required this.redirectUri, required this.rawJson});

  String redirectUri;
  int? expiresIn;
  String? state;
  String? reason;
  String? errorDescription;

  /// The whole `redirect_to_web` body. `request_uri` is in it; the native flow keeps the request
  /// and completes it on `completeWebFallback`.
  String rawJson;
}

class FlowStepMessage {
  FlowStepMessage({required this.kind, required this.challenges});

  FlowStepKind kind;
  List<ChallengeMessage> challenges;

  /// The response's `context` object as JSON text.
  String? contextJson;
  CredentialsMessage? credentials;
  RedirectToWebMessage? redirectToWeb;
}

/// One case of the native `ChallengeAnswer` (spec/03 §4). Passkey, passkey registration and push
/// enrollment answers are built natively by their own calls (spec/18 §5), not here.
enum AnswerKind {
  username,
  password,
  totp,
  otp,
  otpResend,
  updatePassword,
  verifyEmail,
  verifyEmailResend,
  terms,
  recoveryCode,
  pushResend,
  pushPoll,
  pushEnrollmentCheck,
  skip,
  custom,
}

class FormFieldMessage {
  FormFieldMessage({required this.name, required this.value});

  String name;
  String value;
}

class AnswerMessage {
  AnswerMessage({required this.kind});

  AnswerKind kind;

  /// The single value of `username`, `password`, `totp`, `otp`, `verifyEmail` (code),
  /// `recoveryCode`, and the new password of `updatePassword`.
  String? value;

  /// `updatePassword`: the confirmation.
  String? confirm;

  /// `totp`: the chosen authenticator.
  String? credentialId;

  /// `terms`.
  bool? accepted;

  /// `skip` and `custom`: the challenge type on the wire.
  String? type;

  /// `custom`: the form fields in send order.
  List<FormFieldMessage>? fields;
}

class SavedPasswordMessage {
  SavedPasswordMessage({required this.username, required this.password});

  String username;
  String password;
}

class RegisteredPasskeyMessage {
  RegisteredPasskeyMessage({required this.credentialId});

  String credentialId;
  String? label;
}

class PushEnrollmentMessage {
  PushEnrollmentMessage({
    required this.credentialId,
    required this.deviceId,
    required this.userId,
    required this.deviceLabel,
    required this.pushProviderType,
    required this.deviceApiBase,
    required this.keyThumbprint,
    required this.enrolledAtMillis,
  });

  String credentialId;
  String deviceId;
  String userId;
  String? username;
  String deviceLabel;
  String pushProviderType;
  String? pushProviderId;
  String deviceApiBase;
  String keyThumbprint;
  int enrolledAtMillis;
}

/// A pending approval of the push device API (`/login/pending`), as JSON text; Dart reads it.
class PendingApprovalMessage {
  PendingApprovalMessage({required this.cid, required this.rawJson});

  String cid;
  String rawJson;
}

class PushNotificationMessage {
  PushNotificationMessage({required this.cid});

  String cid;
  String? credentialId;
  int? expiresAtMillis;
}

/// One redacted request/response of the SDK's transport (the native `FlowLogEntry`).
class FlowLogMessage {
  FlowLogMessage({
    required this.id,
    required this.timestampMillis,
    required this.method,
    required this.url,
    required this.requestHeaders,
    required this.responseHeaders,
    required this.durationMilliseconds,
  });

  String id;
  int timestampMillis;
  String method;
  String url;
  Map<String, String> requestHeaders;
  String? requestBody;
  int? statusCode;
  Map<String, String> responseHeaders;
  String? responseBody;
  int durationMilliseconds;
  String? errorCode;
}

@FlutterApi()
abstract class KeycloakNativeFlutterApi {
  void onFlowLog(String instance, FlowLogMessage entry);
}

@HostApi()
abstract class KeycloakNativeHostApi {
  /// Creates a native SDK instance and returns its handle.
  String configure(ConfigureMessage config);

  /// A new flow (no request yet); returns the flow handle.
  String startLogin(String instance, LoginParametersMessage parameters);

  /// A step-up flow over the stored post-login `auth_session` (spec/03 §5).
  @async
  String stepUp(String instance, LoginParametersMessage parameters);

  @async
  FlowStepMessage start(String flow);

  /// A step-up flow over the `auth_session` of the last `reauthentication_required` or
  /// `insufficient_authorization` error this instance raised (spec/03 §5, §6).
  @async
  String continueAfterTokenChallenge(String instance, LoginParametersMessage parameters);

  /// Answers the pending challenge `challengeId` of type `challengeType`.
  @async
  FlowStepMessage respond(
    String flow,
    String challengeId,
    String challengeType,
    AnswerMessage answer,
    Map<String, String> additionalFields,
  );

  @async
  void cancel(String flow);

  /// Releases the native flow and the credentials it produced that were not stored.
  void disposeFlow(String flow);

  /// Completes the flow's last `redirect_to_web` step in the system browser (spec/03 §3.4).
  @async
  CredentialsMessage completeWebFallback(String flow);

  /// Stores credentials a flow produced (by handle) in the instance's secure store.
  @async
  void storeCredentials(String instance, String handle);

  /// The stored credentials as they are, possibly expired.
  @async
  CredentialsMessage? storedCredentials(String instance);

  /// Valid credentials, refreshed when within `minTtlSeconds` (plus the SDK's leeway) of expiry.
  @async
  CredentialsMessage credentials(String instance, int minTtlSeconds);

  @async
  bool hasValidCredentials(String instance, int minTtlSeconds);

  /// Server logout with the refresh token (best effort), then clears the store.
  @async
  void logout(String instance);

  @async
  void clearCredentials(String instance);

  /// `Authorization` (and `DPoP`) headers for a resource request with the current credentials.
  @async
  Map<String, String> resourceRequestHeaders(String instance, String method, String url);

  @async
  String? dpopKeyThumbprint(String instance);

  /// The native-auth metadata document as JSON text.
  @async
  String metadataJson(String instance, bool forceRefresh);

  // Ceremonies that answer a challenge natively (spec/18 §5).

  /// Runs the passkey assertion for the pending `passkey` challenge and answers it.
  @async
  FlowStepMessage usePasskey(String flow, String challengeId, bool preferImmediatelyAvailableCredentials);

  /// Runs the passkey registration for the pending `passkey_registration` challenge and answers it.
  @async
  FlowStepMessage registerPasskey(String flow, String challengeId, String? label);

  /// Enrolls this device for push from the pending `push_enrollment` challenge, answers it and keeps
  /// the enrollment once the server accepted it.
  @async
  FlowStepMessage enrollPush(String flow, String challengeId, String deviceLabel, String pushProviderType, String? pushProviderId);

  // Passkeys and passwords outside a flow.

  /// Registers a new passkey for the signed-in user (spec/03 §6) with the stored credentials.
  @async
  RegisteredPasskeyMessage registerNewPasskey(String instance, String? label);

  /// The system sheet of saved passwords.
  @async
  SavedPasswordMessage pickSavedPassword(String instance);

  /// Offers to save a typed password (Android Credential Manager; iOS saves through AutoFill).
  @async
  void savePassword(String instance, String username, String password);

  // Push MFA device side (spec/03 §7).

  @async
  PushEnrollmentMessage? pushEnrollment(String instance);

  @async
  PushEnrollmentMessage pushEnroll(String instance, String deviceLabel, String pushProviderType, String? pushProviderId);

  @async
  void pushForgetEnrollment(String instance);

  @async
  List<PendingApprovalMessage> pushPendingApprovals(String instance);

  /// Approves (with the picked number or PIN) or denies; returns the server's status.
  @async
  String pushRespond(String instance, String cid, bool approve, String? userVerification);

  /// Reads a push message's data (FCM `data`, APNs `userInfo`); null when it is not a sign-in request.
  @async
  PushNotificationMessage? pushHandleMessage(String instance, Map<String, String> data);

  @async
  void pushUpdateProvider(String instance, String type, String id);

  @async
  void pushRotateKey(String instance);

  @async
  void pushLockout(String instance);
}
