import 'dart:async';

import 'package:flutter/foundation.dart';

import 'credentials.dart';
import 'errors.dart';
import 'flow.dart';
import 'mapping.dart';
import 'messages.g.dart';
import 'push.dart';

/// How proofs of possession are made (spec/03 §8); the native SDKs' `DPoPMode`.
enum DPoPMode {
  /// Hardware-backed key when the device has one (Secure Enclave, Android Keystore), else software.
  automatic,

  /// Hardware only; fails with `dpop_key_error` without it.
  hardware,
  software,
  disabled,
}

/// Configuration of one SDK instance; the platform pieces (Keychain or Keystore storage, hardware
/// DPoP keys, passkeys, the browser) are always the native SDKs' own.
final class KeycloakNativeOptions {
  const KeycloakNativeOptions({
    this.dpop = DPoPMode.automatic,
    this.allowRpIdMismatch = false,
    this.ephemeralWebSession = false,
    this.storageNamespace,
    this.metadataCacheTtl,
    this.observeFlow = false,
  });

  final DPoPMode dpop;

  /// Accept a passkey `rp_id` that is neither the issuer host nor a registrable suffix of it. Only
  /// for development against a tunnel (spec/12).
  final bool allowRpIdMismatch;

  /// A browser session that shares no cookies with the user's normal browsing, for the fallback.
  final bool ephemeralWebSession;

  /// Android: the `KeystoreSecureStore` namespace (default: the client id). Give each instance its own.
  final String? storageNamespace;
  final Duration? metadataCacheTtl;

  /// Publish the SDK's redacted request/response entries on `KeycloakNative.flowLog` (a
  /// diagnostics screen). Secrets are masked natively before they reach Dart.
  final bool observeFlow;
}

/// One redacted request/response of the SDK (the native `FlowLogEntry`).
final class FlowLogEntry {
  const FlowLogEntry({
    required this.id,
    required this.timestamp,
    required this.method,
    required this.url,
    required this.requestHeaders,
    required this.responseHeaders,
    required this.duration,
    this.requestBody,
    this.statusCode,
    this.responseBody,
    this.errorCode,
  });

  final String id;
  final DateTime timestamp;
  final String method;
  final Uri url;
  final Map<String, String> requestHeaders;
  final String? requestBody;
  final int? statusCode;
  final Map<String, String> responseHeaders;
  final String? responseBody;
  final Duration duration;

  /// The error code when the request failed.
  final String? errorCode;
}

/// Routes the native flow log to the instance it belongs to.
final class _FlowLogDispatcher implements KeycloakNativeFlutterApi {
  static final _FlowLogDispatcher shared = _FlowLogDispatcher();
  final Map<String, StreamController<FlowLogEntry>> controllers = {};
  bool _registered = false;

  void register(String instance, StreamController<FlowLogEntry> controller) {
    if (!_registered) {
      KeycloakNativeFlutterApi.setUp(this);
      _registered = true;
    }
    controllers[instance] = controller;
  }

  @override
  void onFlowLog(String instance, FlowLogMessage m) => controllers[instance]?.add(
    FlowLogEntry(
      id: m.id,
      timestamp: DateTime.fromMillisecondsSinceEpoch(m.timestampMillis, isUtc: true),
      method: m.method,
      url: Uri.parse(m.url),
      requestHeaders: m.requestHeaders,
      requestBody: m.requestBody,
      statusCode: m.statusCode,
      responseHeaders: m.responseHeaders,
      responseBody: m.responseBody,
      duration: Duration(milliseconds: m.durationMilliseconds),
      errorCode: m.errorCode,
    ),
  );
}

/// A passkey registered with `Passkeys.registerNewPasskey`.
final class RegisteredPasskey {
  const RegisteredPasskey(this.credentialId, this.label);

  final String credentialId;
  final String? label;
}

/// A password picked from the system's saved passwords.
final class SavedPassword {
  const SavedPassword(this.username, this.password);

  final String username;
  final String password;

  @override
  String toString() => 'SavedPassword($username, ***)';
}

/// The configured SDK instance (spec/05 §2): one per issuer and client, backed by a native
/// `KeycloakNative` of the iOS or Android SDK. Keep one per issuer and client for the life of the
/// app, so credentials, the DPoP key and refreshes stay consistent.
final class KeycloakNative {
  KeycloakNative._(this._api, this.handle, this.issuer, this.clientId);

  final KeycloakNativeHostApi _api;

  /// The native instance's handle.
  final String handle;
  final Uri issuer;
  final String clientId;

  /// Creates the native instance. [issuer] includes `/realms/<realm>`.
  static Future<KeycloakNative> configure({
    required Uri issuer,
    required String clientId,
    KeycloakNativeOptions options = const KeycloakNativeOptions(),
    @visibleForTesting KeycloakNativeHostApi? hostApi,
  }) async {
    final api = hostApi ?? KeycloakNativeHostApi();
    final handle = await bridged(
      () => api.configure(
        ConfigureMessage(
          issuer: issuer.toString(),
          clientId: clientId,
          dpop: DPoPModeMessage.values.byName(options.dpop.name),
          allowRpIdMismatch: options.allowRpIdMismatch,
          ephemeralWebSession: options.ephemeralWebSession,
          storageNamespace: options.storageNamespace,
          metadataCacheTtlSeconds: options.metadataCacheTtl?.inSeconds,
          observeFlow: options.observeFlow,
        ),
      ),
    );
    final kc = KeycloakNative._(api, handle, issuer, clientId);
    if (options.observeFlow) _FlowLogDispatcher.shared.register(handle, kc._flowLog);
    return kc;
  }

  final StreamController<FlowLogEntry> _flowLog = StreamController.broadcast();

  /// The SDK's redacted requests and responses, when `KeycloakNativeOptions.observeFlow` is set.
  Stream<FlowLogEntry> get flowLog => _flowLog.stream;

  /// Passkey registration outside a login (spec/03 §6).
  late final Passkeys passkeys = Passkeys._(this);

  /// Push MFA for this device.
  late final Push push = Push.internal(_api, handle);

  /// Shows the system sheet of saved passwords (Credential Manager, iOS AutoFill passwords). Errors:
  /// `saved_password_cancelled`, `saved_password_unavailable`.
  Future<SavedPassword> pickSavedPassword() async {
    final m = await bridged(() => _api.pickSavedPassword(handle));
    return SavedPassword(m.username, m.password);
  }

  /// Offers to save a typed password after the flow ended in `AuthorizedStep` (Android Credential
  /// Manager; on iOS AutoFill offers it by itself and this does nothing).
  Future<void> savePassword(String username, String password) => bridged(() => _api.savePassword(handle, username, password));

  late final Authentication authentication = Authentication._(this);
  late final CredentialsManager credentialsManager = CredentialsManager._(this);
  late final WebFallback webFallback = WebFallback._(this);

  /// RFC 7638 thumbprint of the DPoP public key (`jkt`), `null` when DPoP is disabled.
  Future<String?> dpopKeyThumbprint() => bridged(() => _api.dpopKeyThumbprint(handle));

  /// The realm's native-auth metadata document.
  Future<Map<String, Object?>> metadata({bool forceRefresh = false}) async =>
      decodeObject(await bridged(() => _api.metadataJson(handle, forceRefresh)));
}

/// Entry point for logins and step-ups (spec/05 §2.2).
final class Authentication {
  Authentication._(this._kc);

  final KeycloakNative _kc;

  /// Creates a flow with a fresh PKCE pair; nothing is sent until `start()`.
  Future<NativeLoginFlow> startLogin([LoginParameters parameters = const LoginParameters()]) async {
    final handle = await bridged(() => _kc._api.startLogin(_kc.handle, parametersToMessage(parameters)));
    return NativeLoginFlow.internal(_kc._api, handle, isStepUp: false);
  }

  /// Step-up or re-authentication inside the stored session (spec/03 §5). Throws
  /// `credentials_not_found` when no post-login session is stored.
  Future<NativeLoginFlow> stepUp([LoginParameters parameters = const LoginParameters()]) async {
    final handle = await bridged(() => _kc._api.stepUp(_kc.handle, parametersToMessage(parameters)));
    return NativeLoginFlow.internal(_kc._api, handle, isStepUp: true);
  }

  /// Continues after a call failed with `reauthentication_required` or `insufficient_authorization`
  /// carrying a session (refresh, resource request headers, passkey registration): a step-up flow over
  /// that session, with the `max_age` the server named. The session value stays native.
  Future<NativeLoginFlow> continueAfterTokenChallenge([LoginParameters parameters = const LoginParameters()]) async {
    final handle = await bridged(() => _kc._api.continueAfterTokenChallenge(_kc.handle, parametersToMessage(parameters)));
    return NativeLoginFlow.internal(_kc._api, handle, isStepUp: true);
  }
}

/// Passkeys outside a login.
final class Passkeys {
  Passkeys._(this._kc);

  final KeycloakNative _kc;

  /// Registers a new passkey for the signed-in user with the stored credentials. A stale login is
  /// `insufficient_authorization`: run `Authentication.continueAfterTokenChallenge` and retry.
  Future<RegisteredPasskey> registerNewPasskey({String? label}) async {
    final m = await bridged(() => _kc._api.registerNewPasskey(_kc.handle, label));
    return RegisteredPasskey(m.credentialId, m.label);
  }
}

/// The browser fallback (spec/03 §3.4): ASWebAuthenticationSession on iOS, Auth Tab or a Custom
/// Tab on Android.
final class WebFallback {
  WebFallback._(this._kc);

  final KeycloakNative _kc;

  /// Opens the browser for the flow's last `RedirectToWebStep` and exchanges the code with the
  /// flow's PKCE verifier. Errors: `web_fallback_cancelled` (the user closed the browser; the app may
  /// retry), `web_fallback_failed`, `invalid_response`, and token endpoint errors.
  Future<Credentials> complete(NativeLoginFlow flow) async =>
      credentialsFromMessage(await bridged(() => _kc._api.completeWebFallback(flow.handle)));
}

/// Credentials in the native secure store (Keychain, Android Keystore) with serialized refresh.
final class CredentialsManager {
  CredentialsManager._(this._kc);

  final KeycloakNative _kc;

  /// Stores credentials a flow or the browser fallback produced. Credentials read from the store
  /// are stored already.
  Future<void> store(Credentials credentials) async {
    final handle = credentials.handle;
    if (handle == null) return;
    await bridged(() => _kc._api.storeCredentials(_kc.handle, handle));
  }

  /// The stored credentials as they are, possibly expired; `null` when none.
  Future<Credentials?> stored() async {
    final message = await bridged(() => _kc._api.storedCredentials(_kc.handle));
    return message == null ? null : credentialsFromMessage(message);
  }

  /// Valid credentials, refreshed (once, even under concurrent callers) when the access token is
  /// within [minTtl] plus the SDK's leeway of expiry. Throws `credentials_not_found` or
  /// `reauthentication_required`.
  Future<Credentials> credentials({Duration minTtl = Duration.zero}) async =>
      credentialsFromMessage(await bridged(() => _kc._api.credentials(_kc.handle, minTtl.inSeconds)));

  Future<bool> hasValid({Duration minTtl = Duration.zero}) => bridged(() => _kc._api.hasValidCredentials(_kc.handle, minTtl.inSeconds));

  /// Best-effort server logout with the refresh token, then clears the store.
  Future<void> logout() => bridged(() => _kc._api.logout(_kc.handle));

  Future<void> clear() => bridged(() => _kc._api.clearCredentials(_kc.handle));

  /// Headers for a resource request with the current credentials: `Authorization: Bearer …`, or
  /// `Authorization: DPoP …` plus a `DPoP` proof bound to [method] and [url] (spec/03 §8).
  Future<Map<String, String>> resourceRequestHeaders(String method, Uri url) =>
      bridged(() => _kc._api.resourceRequestHeaders(_kc.handle, method, url.toString()));
}
