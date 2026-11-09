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
}
