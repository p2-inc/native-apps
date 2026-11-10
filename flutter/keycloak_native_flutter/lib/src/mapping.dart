// Pigeon messages <-> the public Dart model. Internal: apps see only the model.
import 'dart:convert';

import 'answers.dart';
import 'challenges.dart';
import 'credentials.dart';
import 'flow.dart';
import 'messages.g.dart';

Map<String, Object?> decodeObject(String? json) {
  if (json == null || json.isEmpty) return const {};
  final decoded = jsonDecode(json);
  return decoded is Map ? decoded.cast<String, Object?>() : const {};
}

Challenge challengeFromMessage(ChallengeMessage m) => Challenge.fromDescriptor(
  ChallengeDescriptor(
    id: m.id,
    type: ChallengeType.fromWire(m.type),
    label: m.label,
    required: m.required,
    error: m.errorCode == null ? null : ChallengeError(m.errorCode!, m.errorMessage),
    hasRetry: m.hasRetry ?? false,
    retryRemaining: m.retryRemaining,
    isSkippable: m.skippable,
    params: decodeObject(m.paramsJson),
  ),
);

Credentials credentialsFromMessage(CredentialsMessage m) => Credentials(
  accessToken: m.accessToken,
  tokenType: m.tokenType,
  idToken: m.idToken,
  scope: m.scope,
  expiresAt: DateTime.fromMillisecondsSinceEpoch(m.expiresAtMillis, isUtc: true),
  refreshExpiresAt: m.refreshExpiresAtMillis == null ? null : DateTime.fromMillisecondsSinceEpoch(m.refreshExpiresAtMillis!, isUtc: true),
  issuedAt: DateTime.fromMillisecondsSinceEpoch(m.issuedAtMillis, isUtc: true),
  hasRefreshToken: m.hasRefreshToken,
  handle: m.handle.isEmpty ? null : m.handle,
);

RedirectToWebRequest redirectFromMessage(RedirectToWebMessage m) => RedirectToWebRequest(
  redirectUri: m.redirectUri,
  expiresIn: m.expiresIn,
  state: m.state,
  reason: m.reason,
  errorDescription: m.errorDescription,
  raw: decodeObject(m.rawJson),
);

FlowStep flowStepFromMessage(FlowStepMessage m) => switch (m.kind) {
  FlowStepKind.challenges => ChallengesStep(
    [for (final c in m.challenges) challengeFromMessage(c)],
    FlowContext(decodeObject(m.contextJson)),
  ),
  FlowStepKind.authorized => AuthorizedStep(credentialsFromMessage(m.credentials!)),
  FlowStepKind.redirectToWeb => RedirectToWebStep(redirectFromMessage(m.redirectToWeb!)),
};

AnswerMessage answerToMessage(ChallengeAnswer answer) => switch (answer) {
  UsernameAnswer(:final username) => AnswerMessage(kind: AnswerKind.username, value: username),
  PasswordAnswer(:final password) => AnswerMessage(kind: AnswerKind.password, value: password),
  TotpAnswer(:final code, :final credentialId) => AnswerMessage(kind: AnswerKind.totp, value: code, credentialId: credentialId),
  OtpAnswer(:final code) => AnswerMessage(kind: AnswerKind.otp, value: code),
  OtpResendAnswer() => AnswerMessage(kind: AnswerKind.otpResend),
  UpdatePasswordAnswer(:final password, :final confirm) => AnswerMessage(kind: AnswerKind.updatePassword, value: password, confirm: confirm),
  VerifyEmailAnswer(:final code) => AnswerMessage(kind: AnswerKind.verifyEmail, value: code),
  VerifyEmailResendAnswer() => AnswerMessage(kind: AnswerKind.verifyEmailResend),
  TermsAnswer(:final accepted) => AnswerMessage(kind: AnswerKind.terms, accepted: accepted),
  RecoveryCodeAnswer(:final code) => AnswerMessage(kind: AnswerKind.recoveryCode, value: code),
  PushResendAnswer() => AnswerMessage(kind: AnswerKind.pushResend),
  PushPollAnswer() => AnswerMessage(kind: AnswerKind.pushPoll),
  PushEnrollmentCheckAnswer() => AnswerMessage(kind: AnswerKind.pushEnrollmentCheck),
  SkipAnswer(:final type) => AnswerMessage(kind: AnswerKind.skip, type: type.wire),
  CustomAnswer(:final type, :final fields) => AnswerMessage(
    kind: AnswerKind.custom,
    type: type.wire,
    fields: [for (final (name, value) in fields) FormFieldMessage(name: name, value: value)],
  ),
};

LoginParametersMessage parametersToMessage(LoginParameters p) => LoginParametersMessage(
  scope: p.scope,
  acrValues: p.acrValues,
  loginHint: p.loginHint,
  prompt: p.prompt,
  maxAge: p.maxAge,
  nonce: p.nonce,
  uiLocales: p.uiLocales,
  deviceName: p.deviceName,
  deviceId: p.deviceId,
  additionalParameters: p.additionalParameters,
  continuationParameters: p.continuationParameters,
);
