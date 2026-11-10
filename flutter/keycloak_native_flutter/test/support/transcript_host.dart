// A fake native side for the Dart layer, fed from the server's recorded transcripts
// (keycloak-native-auth/demo/transcripts, read in place like the iOS and Android SDK tests do).
//
// It stands in for the native SDK: each `start` / `respond` checks the request the native SDK
// would send against the next recorded request, and answers with the recorded response turned into
// the Pigeon messages the bridges build. A server change that adds, renames or drops a field fails
// these tests as it fails the native replay suites.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:keycloak_native_flutter/src/messages.g.dart';

/// The transcripts directory: `KEYCLOAK_NATIVE_TRANSCRIPTS`, else the repository's.
Directory transcriptsDirectory() {
  final override = Platform.environment['KEYCLOAK_NATIVE_TRANSCRIPTS'];
  if (override != null && override.isNotEmpty) return Directory(override);
  // flutter test runs with the package root as the working directory.
  return Directory('../../keycloak-native-auth/demo/transcripts');
}

List<File> allTranscripts() =>
    transcriptsDirectory().listSync().whereType<File>().where((f) => f.path.endsWith('.json')).toList()
      ..sort((a, b) => a.path.compareTo(b.path));

Map<String, Object?> loadTranscript(String name) =>
    (jsonDecode(File('${transcriptsDirectory().path}/$name.json').readAsStringSync()) as Map).cast<String, Object?>();

/// The form fields the native SDKs' `ChallengeAnswer.formFields` produce for [answer]: the
/// contract both bridges implement (ChallengeModels.kt / ChallengeModels.swift).
List<(String, String)> nativeFormFields(AnswerMessage answer) => switch (answer.kind) {
  AnswerKind.username => [('username', answer.value!)],
  AnswerKind.password => [('password', answer.value!)],
  AnswerKind.totp => [('totp', answer.value!), if (answer.credentialId case final id? when id.isNotEmpty) ('credential_id', id)],
  AnswerKind.otp => [('otp', answer.value!)],
  AnswerKind.otpResend || AnswerKind.verifyEmailResend || AnswerKind.pushResend => [('action', 'resend')],
  AnswerKind.updatePassword => [('password', answer.value!), ('password_confirm', answer.confirm!)],
  AnswerKind.verifyEmail => [('code', answer.value!)],
  AnswerKind.terms => [('accepted', '${answer.accepted ?? false}')],
  AnswerKind.recoveryCode => [('recovery_code', answer.value!)],
  AnswerKind.pushPoll => [('action', 'poll')],
  AnswerKind.pushEnrollmentCheck => [('action', 'check')],
  AnswerKind.skip => [('action', 'skip')],
  AnswerKind.custom => [for (final f in answer.fields ?? <FormFieldMessage>[]) (f.name, f.value)],
};

/// Request fields whose recorded value differs per run; only their presence is compared.
const presenceOnlyFields = {'code_challenge', 'device_id', 'nonce'};

class TranscriptMismatch implements Exception {
  TranscriptMismatch(this.message);
  final String message;
  @override
  String toString() => 'TranscriptMismatch: $message';
}

class TranscriptHostApi implements KeycloakNativeHostApi {
  TranscriptHostApi(Map<String, Object?> transcript)
    : _exchanges = [for (final e in transcript['exchanges'] as List) (e as Map).cast<String, Object?>()];

  final List<Map<String, Object?>> _exchanges;
  int _cursor = 0;

  String? _clientId;
  String? _authSession;
  LoginParametersMessage? _parameters;
  final List<String> stored = [];
  int flowsDisposed = 0;

  /// Requests consumed so far.
  int get consumed => _cursor;

  /// Continues the replay at the exchange with [seq] (another device's part of a scenario).
  void skipTo(int seq) => _cursor = _exchanges.indexWhere((e) => e['seq'] == seq);

  @override
  Future<String> configure(ConfigureMessage config) async {
    _clientId = config.clientId;
    return 'instance';
  }

  @override
  Future<String> startLogin(String instance, LoginParametersMessage parameters) async {
    _parameters = parameters;
    return 'flow';
  }

  @override
  Future<FlowStepMessage> start(String flow) async {
    final p = _parameters!;
    final expected = <(String, String)>[
      ('client_id', _clientId!),
      ('response_type', 'code'),
      if (p.scope case final scope? when scope.isNotEmpty) ('scope', scope),
      ('code_challenge', '<per run>'),
      ('code_challenge_method', 'S256'),
      if (p.acrValues case final v?) ('acr_values', v),
      if (p.loginHint case final v?) ('login_hint', v),
      if (p.prompt case final v?) ('prompt', v),
      if (p.maxAge case final v?) ('max_age', '$v'),
      if (p.nonce case final v?) ('nonce', v),
      if (p.uiLocales case final v?) ('ui_locales', v),
      if (p.deviceName case final v?) ('device_name', v),
      if (p.deviceId case final v?) ('device_id', v),
      ...(p.additionalParameters.entries.toList()..sort((a, b) => a.key.compareTo(b.key))).map((e) => (e.key, e.value)),
    ];
    return _challengeExchange(expected);
  }

  @override
  Future<FlowStepMessage> respond(
    String flow,
    String challengeId,
    String challengeType,
    AnswerMessage answer,
    Map<String, String> additionalFields,
  ) async {
    final p = _parameters!;
    final expected = <(String, String)>[
      ('auth_session', _authSession ?? '<none>'),
      ('challenge_type', challengeType),
      ('challenge_id', challengeId),
      ...nativeFormFields(answer),
      ...(p.continuationParameters.entries.toList()..sort((a, b) => a.key.compareTo(b.key))).map((e) => (e.key, e.value)),
      ...(additionalFields.entries.toList()..sort((a, b) => a.key.compareTo(b.key))).map((e) => (e.key, e.value)),
    ];
    return _challengeExchange(expected);
  }

  /// A native ceremony (passkey, push enrollment): its fields come from the platform, so only the
  /// routing and the field names are compared; the recorded values stand in for the platform's.
  Future<FlowStepMessage> _ceremony(String challengeId, String challengeType, Set<String> required, {Set<String> optional = const {}}) {
    final recorded = _form(_exchanges[_cursor < _exchanges.length ? _cursor : _exchanges.length - 1]);
    final answer = recorded.keys.toSet().difference({'auth_session', 'challenge_type', 'challenge_id'});
    if (!answer.containsAll(required) || !optional.union(required).containsAll(answer)) {
      throw TranscriptMismatch('Ceremony fields: recorded $answer, the native SDK sends $required + optional $optional');
    }
    final expected = <(String, String)>[
      ('auth_session', _authSession ?? '<none>'),
      ('challenge_type', challengeType),
      ('challenge_id', challengeId),
      for (final name in answer) (name, recorded[name]!),
    ];
    return _challengeExchange(expected);
  }

  final List<String> calls = [];

  Future<FlowStepMessage> _challengeExchange(List<(String, String)> expected) async {
    final exchange = _next('/native-auth/challenge');
    _compare(expected, _form(exchange));
    final response = (exchange['response'] as Map).cast<String, Object?>();
    final status = response['status'] as int;
    final body = ((response['json'] as Map?) ?? const {}).cast<String, Object?>();
    if (status == 200 && body['authorization_code'] != null) {
      _authSession = body['auth_session'] as String?;
      return FlowStepMessage(kind: FlowStepKind.authorized, challenges: [], credentials: _tokenExchange(body['authorization_code'] as String));
    }
    final error = body['error'] as String?;
    if (status == 403 && error == 'insufficient_authorization' && body['challenges'] is List) {
      _authSession = body['auth_session'] as String?;
      return FlowStepMessage(
        kind: FlowStepKind.challenges,
        challenges: [for (final c in body['challenges'] as List) _challenge((c as Map).cast<String, Object?>())],
        contextJson: jsonEncode(body['context'] ?? const {}),
      );
    }
    if (status == 403 && error == 'redirect_to_web') {
      return FlowStepMessage(
        kind: FlowStepKind.redirectToWeb,
        challenges: [],
        redirectToWeb: RedirectToWebMessage(
          redirectUri: body['redirect_uri'] as String,
          expiresIn: body['expires_in'] as int?,
          state: body['state'] as String?,
          reason: body['reason'] as String?,
          errorDescription: body['error_description'] as String?,
          rawJson: jsonEncode(body),
        ),
      );
    }
    throw PlatformException(
      code: error ?? 'invalid_response',
      message: body['error_description'] as String?,
      details: {'statusCode': status, 'isNetworkError': false, 'isRetryable': status >= 500, 'detailsJson': jsonEncode(body)},
    );
  }

  CredentialsMessage _tokenExchange(String code) {
    final now = DateTime.now().millisecondsSinceEpoch;
    final upcoming = _cursor < _exchanges.length ? ((_exchanges[_cursor]['request'] as Map)['path'] as String) : '';
    if (!upcoming.endsWith('/protocol/openid-connect/token')) {
      // Some tests stop at the code; the native SDK's exchange is covered by its own replay suites.
      return CredentialsMessage(
        handle: 'credentials-$_cursor',
        accessToken: 'unrecorded',
        tokenType: 'Bearer',
        expiresAtMillis: now + 300000,
        issuedAtMillis: now,
        hasRefreshToken: true,
      );
    }
    final exchange = _next('/protocol/openid-connect/token');
    _compare([('grant_type', 'authorization_code'), ('client_id', _clientId!), ('code', code), ('code_verifier', '***')], _form(exchange));
    final body = ((exchange['response'] as Map)['json'] as Map).cast<String, Object?>();
    return CredentialsMessage(
      handle: 'credentials-$_cursor',
      accessToken: body['access_token'] as String,
      tokenType: body['token_type'] as String,
      idToken: body['id_token'] as String?,
      scope: body['scope'] as String?,
      expiresAtMillis: now + (body['expires_in'] as int) * 1000,
      refreshExpiresAtMillis: switch (body['refresh_expires_in']) {
        final int s when s > 0 => now + s * 1000,
        _ => null,
      },
      issuedAtMillis: now,
      hasRefreshToken: body['refresh_token'] != null,
    );
  }

  ChallengeMessage _challenge(Map<String, Object?> c) {
    final error = (c['error'] as Map?)?.cast<String, Object?>();
    final retry = (c['retry'] as Map?)?.cast<String, Object?>();
    return ChallengeMessage(
      id: c['id'] as String,
      type: c['type'] as String,
      label: c['label'] as String?,
      required: c['required'] as bool? ?? true,
      errorCode: error?['code'] as String?,
      errorMessage: error?['message'] as String?,
      hasRetry: retry != null,
      retryRemaining: retry?['remaining'] as int?,
      skippable: c['skippable'] as bool? ?? false,
      paramsJson: jsonEncode(c['params'] ?? const {}),
    );
  }

  Map<String, Object?> _next(String pathSuffix) {
    if (_cursor >= _exchanges.length) throw TranscriptMismatch('No recorded request left for $pathSuffix');
    final exchange = _exchanges[_cursor++];
    final path = (exchange['request'] as Map)['path'] as String;
    if (!path.endsWith(pathSuffix)) throw TranscriptMismatch('Expected a request to $pathSuffix, the transcript has $path (seq ${exchange['seq']})');
    return exchange;
  }

  Map<String, String> _form(Map<String, Object?> exchange) =>
      (((exchange['request'] as Map)['form'] as Map?) ?? const {}).map((k, v) => MapEntry(k as String, v as String));

  void _compare(List<(String, String)> expected, Map<String, String> recorded) {
    final names = [for (final (name, _) in expected) name];
    if (names.toSet().length != names.length) throw TranscriptMismatch('Duplicate field in $names');
    if (!_sameSet(names.toSet(), recorded.keys.toSet())) {
      throw TranscriptMismatch('Field set differs: sent ${names.toSet()}, recorded ${recorded.keys.toSet()}');
    }
    for (final (name, value) in expected) {
      final recordedValue = recorded[name]!;
      if (presenceOnlyFields.contains(name) || recordedValue == '***') continue;
      if (recordedValue != value) throw TranscriptMismatch('$name: sent "$value", recorded "$recordedValue"');
    }
  }

  static bool _sameSet(Set<String> a, Set<String> b) => a.length == b.length && a.containsAll(b);

  @override
  Future<FlowStepMessage> usePasskey(String flow, String challengeId, bool preferImmediatelyAvailableCredentials) async {
    calls.add('usePasskey');
    return _ceremony(challengeId, 'passkey', {'credential_id', 'client_data_json', 'authenticator_data', 'signature'}, optional: {'user_handle'});
  }

  @override
  Future<FlowStepMessage> registerPasskey(String flow, String challengeId, String? label) async {
    calls.add('registerPasskey:$label');
    return _ceremony(challengeId, 'passkey_registration', {'credential_id', 'client_data_json', 'attestation_object'}, optional: {'transports', 'label'});
  }

  @override
  Future<FlowStepMessage> enrollPush(String flow, String challengeId, String deviceLabel, String pushProviderType, String? pushProviderId) async {
    calls.add('enrollPush:$deviceLabel:$pushProviderType');
    return _ceremony(challengeId, 'push_enrollment', {'token'});
  }

  @override
  Future<List<PendingApprovalMessage>> pushPendingApprovals(String instance) async {
    final exchange = _next('/push-mfa/login/pending');
    final body = ((exchange['response'] as Map)['json'] as Map).cast<String, Object?>();
    return [
      for (final c in body['challenges'] as List) PendingApprovalMessage(cid: (c as Map)['cid'] as String, rawJson: jsonEncode(c)),
    ];
  }

  @override
  Future<String> pushRespond(String instance, String cid, bool approve, String? userVerification) async {
    calls.add('pushRespond:$cid:$approve:$userVerification');
    final exchange = _next('/login/challenges/$cid/respond');
    final response = (exchange['response'] as Map).cast<String, Object?>();
    final body = ((response['json'] as Map?) ?? const {}).cast<String, Object?>();
    if (response['status'] != 200) {
      // The SDKs map ba-itsys' 403 sentence to their own code (spec/17 §6 step 9).
      throw PlatformException(code: response['status'] == 403 ? 'user_verification_mismatch' : 'invalid_response', message: body['error'] as String?);
    }
    return body['status'] as String? ?? 'ok';
  }

  // Calls a replay does not reach.

  @override
  Future<String> continueAfterTokenChallenge(String instance, LoginParametersMessage parameters) async => startLogin(instance, parameters);

  @override
  Future<RegisteredPasskeyMessage> registerNewPasskey(String instance, String? label) async => RegisteredPasskeyMessage(credentialId: 'c', label: label);

  SavedPasswordMessage? savedPassword;
  final List<(String, String)> savedPasswords = [];

  @override
  Future<SavedPasswordMessage> pickSavedPassword(String instance) async =>
      savedPassword ?? (throw PlatformException(code: 'saved_password_cancelled', message: 'Closed'));

  @override
  Future<void> savePassword(String instance, String username, String password) async => savedPasswords.add((username, password));

  @override
  Future<PushEnrollmentMessage?> pushEnrollment(String instance) async => null;

  @override
  Future<PushEnrollmentMessage> pushEnroll(String instance, String deviceLabel, String pushProviderType, String? pushProviderId) async =>
      throw PlatformException(code: 'push_unavailable');

  @override
  Future<void> pushForgetEnrollment(String instance) async {}

  @override
  Future<PushNotificationMessage?> pushHandleMessage(String instance, Map<String, String> data) async => null;

  @override
  Future<void> pushUpdateProvider(String instance, String type, String id) async {}

  @override
  Future<void> pushRotateKey(String instance) async {}

  @override
  Future<void> pushLockout(String instance) async {}

  @override
  Future<String> stepUp(String instance, LoginParametersMessage parameters) async => startLogin(instance, parameters);

  @override
  Future<void> cancel(String flow) async {}

  @override
  Future<void> disposeFlow(String flow) async => flowsDisposed++;

  @override
  Future<CredentialsMessage> completeWebFallback(String flow) async => throw PlatformException(code: 'web_fallback_cancelled', message: 'The user closed the browser');

  @override
  Future<void> storeCredentials(String instance, String handle) async => stored.add(handle);

  @override
  Future<CredentialsMessage?> storedCredentials(String instance) async => null;

  @override
  Future<CredentialsMessage> credentials(String instance, int minTtlSeconds) async =>
      throw PlatformException(code: 'credentials_not_found', message: 'No stored credentials');

  @override
  Future<bool> hasValidCredentials(String instance, int minTtlSeconds) async => false;

  @override
  Future<void> logout(String instance) async {}

  @override
  Future<void> clearCredentials(String instance) async {}

  @override
  Future<Map<String, String>> resourceRequestHeaders(String instance, String method, String url) async => {};

  @override
  Future<String?> dpopKeyThumbprint(String instance) async => null;

  @override
  Future<String> metadataJson(String instance, bool forceRefresh) async => '{}';

  @override
  // ignore: non_constant_identifier_names
  BinaryMessenger? get pigeonVar_binaryMessenger => null;

  @override
  // ignore: non_constant_identifier_names
  String get pigeonVar_messageChannelSuffix => '';
}
