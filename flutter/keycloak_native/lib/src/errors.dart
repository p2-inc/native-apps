import 'dart:convert';

import 'package:flutter/services.dart';

/// The single error type of the plugin, carrying the native SDKs' `NativeAuthError`. Branch on
/// [code], never on messages: the codes are the iOS and Android SDKs' (see [NativeAuthErrorCode]),
/// and server codes pass through unchanged.
final class NativeAuthException implements Exception {
  const NativeAuthException(
    this.code, {
    this.description,
    this.statusCode,
    this.isNetworkError = false,
    this.isRetryable = false,
    this.retryAfter,
    this.maxAge,
    this.details,
  });

  /// Maps the `PlatformException` the bridge raises for a native `NativeAuthError`.
  factory NativeAuthException.fromPlatformException(PlatformException e) {
    final details = e.details is Map ? (e.details as Map).cast<String, Object?>() : const <String, Object?>{};
    final detailsJson = details['detailsJson'];
    Object? body;
    if (detailsJson is String) {
      try {
        body = jsonDecode(detailsJson);
      } on FormatException {
        body = null;
      }
    }
    return NativeAuthException(
      e.code,
      description: e.message,
      statusCode: details['statusCode'] as int?,
      isNetworkError: details['isNetworkError'] as bool? ?? false,
      isRetryable: details['isRetryable'] as bool? ?? false,
      retryAfter: details['retryAfter'] as double?,
      maxAge: details['maxAge'] as int?,
      details: body is Map ? body.cast<String, Object?>() : null,
    );
  }

  final String code;
  final String? description;
  final int? statusCode;
  final bool isNetworkError;

  /// `true` for transient conditions (network, `slow_down`, `server_error`).
  final bool isRetryable;

  /// `Retry-After` in seconds for `slow_down`.
  final double? retryAfter;

  /// `max_age` of an `insufficient_authorization` answer: the freshness a step-up must satisfy.
  final int? maxAge;

  /// The error response's JSON body, when there was one.
  final Map<String, Object?>? details;

  @override
  String toString() => 'NativeAuthException($code${statusCode == null ? '' : ' http=$statusCode'}${description == null ? '' : ' "$description"'})';
}

/// The stable error codes shared with the native SDKs (spec/05 §2.3).
abstract final class NativeAuthErrorCode {
  // spec/03 §3.5 (challenge endpoint)
  static const invalidRequest = 'invalid_request';
  static const invalidSession = 'invalid_session';
  static const invalidDPoPProof = 'invalid_dpop_proof';
  static const invalidClient = 'invalid_client';
  static const accessDenied = 'access_denied';
  static const slowDown = 'slow_down';
  static const serverError = 'server_error';
  static const redirectToWeb = 'redirect_to_web';

  // spec/03 §6 and the token endpoint
  static const invalidToken = 'invalid_token';
  static const insufficientAuthorization = 'insufficient_authorization';
  static const invalidGrant = 'invalid_grant';

  // SDK-local
  static const networkError = 'network_error';
  static const invalidResponse = 'invalid_response';
  static const metadataUnavailable = 'metadata_unavailable';
  static const unsupportedChallenge = 'unsupported_challenge';
  static const flowState = 'flow_state';
  static const invalidParameter = 'invalid_parameter';
  static const passkeyCancelled = 'passkey_cancelled';
  static const passkeyFailed = 'passkey_failed';
  static const passkeyUnavailable = 'passkey_unavailable';
  static const rpIdMismatch = 'rp_id_mismatch';
  static const credentialsNotFound = 'credentials_not_found';
  static const reauthenticationRequired = 'reauthentication_required';
  static const keychainError = 'keychain_error';
  static const keychainAuthenticationFailed = 'keychain_authentication_failed';
  static const dpopKeyError = 'dpop_key_error';
  static const webFallbackCancelled = 'web_fallback_cancelled';
  static const webFallbackFailed = 'web_fallback_failed';
  static const savedPasswordCancelled = 'saved_password_cancelled';
  static const savedPasswordUnavailable = 'saved_password_unavailable';
}

/// Runs a host call, turning a `PlatformException` into a [NativeAuthException].
Future<T> bridged<T>(Future<T> Function() call) async {
  try {
    return await call();
  } on PlatformException catch (e) {
    throw NativeAuthException.fromPlatformException(e);
  }
}
