import 'dart:convert';

/// Challenge types of spec/03 §4. Types this version cannot name are kept as [ChallengeType.unknown]
/// values with their wire string, so an app can show "update the app or use the web" (spec/03
/// §4.11). Two types are equal when their [wire] values are.
final class ChallengeType {
  const ChallengeType._(this.wire);

  /// A type this version of the plugin does not know.
  const ChallengeType.unknown(this.wire);

  final String wire;

  static const username = ChallengeType._('username');
  static const password = ChallengeType._('password');
  static const passkey = ChallengeType._('passkey');
  static const passkeyRegistration = ChallengeType._('passkey_registration');
  static const totp = ChallengeType._('totp');
  static const otp = ChallengeType._('otp');
  static const push = ChallengeType._('push');
  static const recoveryCode = ChallengeType._('recovery_code');
  static const select = ChallengeType._('select');

  // Native required actions (spec/03 §4.12–§4.15).
  static const updatePassword = ChallengeType._('update_password');
  static const verifyEmail = ChallengeType._('verify_email');
  static const terms = ChallengeType._('terms');
  static const pushEnrollment = ChallengeType._('push_enrollment');

  static const List<ChallengeType> known = [
    username, password, passkey, passkeyRegistration, totp, otp, push, recoveryCode, select, //
    updatePassword, verifyEmail, terms, pushEnrollment,
  ];

  static ChallengeType fromWire(String wire) =>
      known.firstWhere((type) => type.wire == wire, orElse: () => ChallengeType.unknown(wire));

  bool get isKnown => known.contains(this);

  /// Whether the native SDKs have an answer for the type (their `isSupported`). `select` is specified
  /// (spec/03 §4.9) but no server-side authenticator emits it yet.
  bool get isSupported => isKnown && this != select;

  /// A required action served in-band (spec/03 §4.11): the single entry of its set, whose `id` is
  /// the native required action's provider id.
  bool get isRequiredAction =>
      this == passkeyRegistration || this == updatePassword || this == verifyEmail || this == terms || this == pushEnrollment;

  @override
  bool operator ==(Object other) => other is ChallengeType && other.wire == wire;

  @override
  int get hashCode => wire.hashCode;

  @override
  String toString() => wire;
}

/// `error` of a descriptor: the previous attempt at this challenge failed (spec/03 §3.3). A value
/// to show next to the field, not a thrown error.
final class ChallengeError {
  const ChallengeError(this.code, this.message);

  final String code;
  final String? message;

  static const invalidCredential = 'invalid_credential';
  static const invalidUser = 'invalid_user';
  static const missingCredential = 'missing_credential';
  static const invalidAttestation = 'invalid_attestation';

  /// `otp`: the code expired or was used up; resend.
  static const expiredCode = 'expired_code';
  static const resendTooSoon = 'resend_too_soon';
  static const passwordMismatch = 'password_mismatch';
  static const invalidPassword = 'invalid_password';
  static const denied = 'denied';
  static const expired = 'expired';

  @override
  bool operator ==(Object other) => other is ChallengeError && other.code == code && other.message == message;

  @override
  int get hashCode => Object.hash(code, message);

  @override
  String toString() => 'ChallengeError($code)';
}

/// The fields every descriptor has (spec/03 §3.3).
final class ChallengeDescriptor {
  const ChallengeDescriptor({
    required this.id,
    required this.type,
    this.label,
    this.required = true,
    this.error,
    this.hasRetry = false,
    this.retryRemaining,
    this.isSkippable = false,
    this.params = const {},
  });

  /// `challenge_id`: the execution id, or the required action's provider id.
  final String id;
  final ChallengeType type;
  final String? label;
  final bool required;
  final ChallengeError? error;
  final bool hasRetry;

  /// Attempts left before the realm's brute-force protection locks the account.
  final int? retryRemaining;

  /// The user may decline this required action for this login with `ChallengeAnswer.skip`.
  final bool isSkippable;

  /// The raw `params` object.
  final Map<String, Object?> params;
}

/// A challenge of the current set, one subclass per type with typed views of `params`. Build an
/// answer with [ChallengeAnswer] and pass it with this challenge to `NativeLoginFlow.respond`.
sealed class Challenge {
  Challenge(this.descriptor);

  final ChallengeDescriptor descriptor;

  String get id => descriptor.id;
  ChallengeType get type => descriptor.type;
  String? get label => descriptor.label;
  bool get required => descriptor.required;
  ChallengeError? get error => descriptor.error;
  int? get retryRemaining => descriptor.retryRemaining;
  bool get isSkippable => descriptor.isSkippable;
  Map<String, Object?> get params => descriptor.params;

  /// The typed subclass for [descriptor.type]; [UnknownChallenge] for types this version cannot name.
  factory Challenge.fromDescriptor(ChallengeDescriptor descriptor) {
    final type = descriptor.type;
    if (type == ChallengeType.username) return UsernameChallenge(descriptor);
    if (type == ChallengeType.password) return PasswordChallenge(descriptor);
    if (type == ChallengeType.totp) return TotpChallenge(descriptor);
    if (type == ChallengeType.otp) return OtpChallenge(descriptor);
    if (type == ChallengeType.passkey) return PasskeyChallenge(descriptor);
    if (type == ChallengeType.passkeyRegistration) return PasskeyRegistrationChallenge(descriptor);
    if (type == ChallengeType.push) return PushChallenge(descriptor);
    if (type == ChallengeType.pushEnrollment) return PushEnrollmentChallenge(descriptor);
    if (type == ChallengeType.recoveryCode) return RecoveryCodeChallenge(descriptor);
    if (type == ChallengeType.updatePassword) return UpdatePasswordChallenge(descriptor);
    if (type == ChallengeType.verifyEmail) return VerifyEmailChallenge(descriptor);
    if (type == ChallengeType.terms) return TermsChallenge(descriptor);
    return UnknownChallenge(descriptor);
  }

  @override
  bool operator ==(Object other) =>
      other is Challenge &&
      other.id == id &&
      other.type == type &&
      other.error == error &&
      other.retryRemaining == retryRemaining &&
      jsonEncode(other.params) == jsonEncode(params);

  @override
  int get hashCode => Object.hash(id, type);

  @override
  String toString() => 'Challenge($type, id=$id)';
}

/// spec/03 §4.1.
final class UsernameChallenge extends Challenge {
  UsernameChallenge(super.descriptor);

  bool get allowEmail => _bool(params['allow_email']) ?? false;
  String? get hint => _string(params['hint']);
}

/// spec/03 §4.2.
final class PasswordChallenge extends Challenge {
  PasswordChallenge(super.descriptor);

  bool get usernameKnown => _bool(params['username_known']) ?? true;
}

/// One enrolled authenticator of a [TotpChallenge].
final class TotpCredential {
  const TotpCredential(this.id, this.label);

  final String id;
  final String label;
}

/// spec/03 §4.5.
final class TotpChallenge extends Challenge {
  TotpChallenge(super.descriptor);

  int get digits => _int(params['digits']) ?? 6;
  int get period => _int(params['period']) ?? 30;
  String? get algorithm => _string(params['algorithm']);
  List<TotpCredential> get credentials => [
    for (final entry in _list(params['credentials']))
      if (_string(_map(entry)['id']) case final id?) TotpCredential(id, _string(_map(entry)['label']) ?? ''),
  ];
}

/// spec/03 §4.6: a code delivered by email or SMS.
final class OtpChallenge extends Challenge {
  OtpChallenge(super.descriptor);

  /// `email` | `sms`
  String get channel => _string(params['channel']) ?? 'email';
  String? get destinationMasked => _string(params['destination_masked']);
  int get digits => _int(params['digits']) ?? 6;
  int? get ttl => _int(params['ttl']);

  /// `false` while the server waits for `ChallengeAnswer.otpResend` to send the first code.
  bool get sent => _bool(params['sent']) ?? false;
  DateTime? get resendAllowedAt => _instant(params['resend_allowed_at']);
}

/// spec/03 §4.3. The ceremony runs in the native SDK (spec/18 §5).
final class PasskeyChallenge extends Challenge {
  PasskeyChallenge(super.descriptor);

  String? get rpId => _string(params['rp_id']);
  String get userVerification => _string(params['user_verification']) ?? 'preferred';

  /// `true` when `allow_credentials` is empty: a username-less login.
  bool get discoverable => _bool(params['discoverable']) ?? _list(params['allow_credentials']).isEmpty;
}

/// spec/03 §4.4. The ceremony runs in the native SDK (spec/18 §5).
final class PasskeyRegistrationChallenge extends Challenge {
  PasskeyRegistrationChallenge(super.descriptor);

  String? get rpId => _string(_map(params['rp'])['id']);
  String? get rpName => _string(_map(params['rp'])['name']);
  String? get userName => _string(_map(params['user'])['name']);
  String? get userDisplayName => _string(_map(params['user'])['display_name']);
}

/// spec/03 §4.7: approve the sign-in on an enrolled device.
final class PushChallenge extends Challenge {
  PushChallenge(super.descriptor);

  bool get sent => _bool(params['sent']) ?? false;
  DateTime? get expiresAt => _instant(params['expires_at']);

  /// Seconds between `ChallengeAnswer.pushPoll` answers.
  int get pollInterval {
    final value = _int(params['poll_interval']) ?? 3;
    return value < 1 ? 1 : value;
  }

  /// `pending` | `approved` | `denied` | `expired`
  String? get status => _string(params['status']);

  /// Number match: the number this client shows; the user picks it on the device.
  String? get userVerificationNumber {
    final verification = _map(params['user_verification']);
    return _string(verification['type']) == 'number_match' ? _string(verification['number']) : null;
  }

  List<String> get devices => [
    for (final device in _list(params['devices']))
      ?_string(_map(device)['label']),
  ];
  DateTime? get resendAllowedAt => _instant(params['resend_allowed_at']);
  bool get isPending => sent && (status == null || status == 'pending');
}

/// spec/03 §4.15. The device key and the enrollment JWT stay in the native SDK (spec/18 §5).
final class PushEnrollmentChallenge extends Challenge {
  PushEnrollmentChallenge(super.descriptor);

  int? get expiresIn => _int(params['expires_in']);
  String? get userId => _string(params['user_id']);
}

/// spec/03 §4.8.
final class RecoveryCodeChallenge extends Challenge {
  RecoveryCodeChallenge(super.descriptor);

  int? get remaining => _int(params['remaining']);
  int? get warningThreshold => _int(params['warning_threshold']);
  bool get shouldWarn => remaining != null && warningThreshold != null && remaining! <= warningThreshold!;
}

/// spec/03 §4.12.
final class UpdatePasswordChallenge extends Challenge {
  UpdatePasswordChallenge(super.descriptor);

  String? get username => _string(params['username']);

  /// Keycloak policy id → configured value (`length: 8`, `digits: 1`, `notUsername: true`, …).
  Map<String, Object?> get policy => _map(params['policy']);
  int? get minimumLength => _int(policy['length']);
  int? get maximumLength => _int(policy['maxLength']);
}

/// spec/03 §4.13.
final class VerifyEmailChallenge extends Challenge {
  VerifyEmailChallenge(super.descriptor);

  String? get emailMasked => _string(params['email_masked']);
  int get digits => _int(params['digits']) ?? 6;
  int? get ttl => _int(params['ttl']);
  bool get sent => _bool(params['sent']) ?? false;
  DateTime? get resendAllowedAt => _instant(params['resend_allowed_at']);
}

/// spec/03 §4.14.
final class TermsChallenge extends Challenge {
  TermsChallenge(super.descriptor);

  String? get text => _string(params['text']);
  Uri? get url => switch (_string(params['url'])) {
    final value? => Uri.tryParse(value),
    null => null,
  };
  String? get version => _string(params['version']);
}

/// A type this version cannot answer (or `select`, which no server emits yet). Answer it with
/// `ChallengeAnswer.custom` if the app knows it, or let the user finish on the web.
final class UnknownChallenge extends Challenge {
  UnknownChallenge(super.descriptor);
}

/// Informational `context` of a challenge response (spec/03 §3.2).
final class FlowContext {
  const FlowContext([this.raw = const {}]);

  final Map<String, Object?> raw;

  String? get username => _string(raw['username']);
  String? get displayName => _string(raw['display_name']);
  String? get clientName => _string(raw['client_name']);
  String? get acrRequested => _string(raw['acr_requested']);
  bool get stepUp => _bool(raw['step_up']) ?? false;
}

/// A `redirect_to_web` answer (spec/03 §3.4): finish this login in the browser.
final class RedirectToWebRequest {
  const RedirectToWebRequest({
    required this.redirectUri,
    this.expiresIn,
    this.state,
    this.reason,
    this.errorDescription,
    this.raw = const {},
  });

  final String redirectUri;
  final int? expiresIn;
  final String? state;

  /// Informational, e.g. `required_action:UPDATE_PASSWORD`.
  final String? reason;
  final String? errorDescription;
  final Map<String, Object?> raw;
}

String? _string(Object? value) => value is String ? value : null;

bool? _bool(Object? value) => value is bool ? value : null;

int? _int(Object? value) => switch (value) {
  final int v => v,
  final double v when v == v.roundToDouble() => v.toInt(),
  _ => null,
};

List<Object?> _list(Object? value) => value is List ? value.cast<Object?>() : const [];

Map<String, Object?> _map(Object? value) => value is Map ? value.cast<String, Object?>() : const {};

/// Seconds since the epoch, as the protocol sends instants.
DateTime? _instant(Object? value) =>
    value is num ? DateTime.fromMillisecondsSinceEpoch((value * 1000).round(), isUtc: true) : null;
