// The Pigeon messages <-> Dart model mapping (spec/18 §4).
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';
import 'package:keycloak_native_flutter/src/mapping.dart';
import 'package:keycloak_native_flutter/src/messages.g.dart';

ChallengeMessage _message(String type, String params, {String? errorCode, int? retry, bool skippable = false}) => ChallengeMessage(
  id: 'id-$type',
  type: type,
  required: true,
  errorCode: errorCode,
  errorMessage: errorCode == null ? null : 'Invalid',
  hasRetry: retry != null,
  retryRemaining: retry,
  skippable: skippable,
  paramsJson: params,
);

void main() {
  group('challenges', () {
    test('each known type maps to its class', () {
      const expected = {
        'username': UsernameChallenge,
        'password': PasswordChallenge,
        'totp': TotpChallenge,
        'otp': OtpChallenge,
        'passkey': PasskeyChallenge,
        'passkey_registration': PasskeyRegistrationChallenge,
        'push': PushChallenge,
        'push_enrollment': PushEnrollmentChallenge,
        'recovery_code': RecoveryCodeChallenge,
        'update_password': UpdatePasswordChallenge,
        'verify_email': VerifyEmailChallenge,
        'terms': TermsChallenge,
        'pin': PinChallenge,
        'pin_setup': PinSetupChallenge,
        'select': UnknownChallenge,
        'x_face_scan': UnknownChallenge,
      };
      expected.forEach((wire, type) {
        final challenge = challengeFromMessage(_message(wire, '{}'));
        expect(challenge.runtimeType, type, reason: wire);
        expect(challenge.type.wire, wire);
      });
    });

    test('unknown types keep their wire value and are unsupported', () {
      final challenge = challengeFromMessage(_message('x_face_scan', '{}'));
      expect(challenge.type, const ChallengeType.unknown('x_face_scan'));
      expect(challenge.type.isSupported, isFalse);
      expect(ChallengeType.select.isSupported, isFalse);
      expect(ChallengeType.totp.isSupported, isTrue);
      expect(ChallengeType.terms.isRequiredAction, isTrue);
      expect(ChallengeType.pinSetup.isRequiredAction, isTrue);
      expect(ChallengeType.pin.isRequiredAction, isFalse);
      expect(ChallengeType.pin.isSupported, isTrue);
    });

    test('pin and pin_setup params, the locked state and the PIN shape', () {
      final pin = challengeFromMessage(_message('pin', '{"length":6}')) as PinChallenge;
      expect(pin.length, 6);
      expect(pin.isLocked, isFalse);
      expect((challengeFromMessage(_message('pin', '{}')) as PinChallenge).length, 4);
      final locked = challengeFromMessage(_message('pin', '{"length":4}', errorCode: 'credential_locked', retry: 0)) as PinChallenge;
      expect(locked.isLocked, isTrue);
      final setup = challengeFromMessage(_message('pin_setup', '{"length":4}')) as PinSetupChallenge;
      expect(setup.isWellFormed('2580'), isTrue);
      expect(setup.isWellFormed('258'), isFalse);
      expect(setup.isWellFormed('25800'), isFalse);
      expect(setup.isWellFormed('25a0'), isFalse);
      expect(setup.isWellFormed('２５８０'), isFalse);
    });

    test('descriptor fields and typed params', () {
      final totp = challengeFromMessage(
            _message(
              'totp',
              '{"digits":8,"period":60,"algorithm":"HmacSHA256","credentials":[{"id":"a","label":"Phone"},{"id":"b","label":"Tablet"},{"label":"no id"}]}',
              errorCode: 'invalid_credential',
              retry: 2,
            ),
          )
          as TotpChallenge;
      expect(totp.digits, 8);
      expect(totp.period, 60);
      expect(totp.algorithm, 'HmacSHA256');
      expect(totp.credentials.map((c) => c.label), ['Phone', 'Tablet']);
      expect(totp.error, const ChallengeError('invalid_credential', 'Invalid'));
      expect(totp.retryRemaining, 2);

      final otp = challengeFromMessage(_message('otp', '{"channel":"sms","sent":true,"resend_allowed_at":1700000000.5}')) as OtpChallenge;
      expect(otp.channel, 'sms');
      expect(otp.sent, isTrue);
      expect(otp.digits, 6);
      expect(otp.resendAllowedAt, DateTime.fromMillisecondsSinceEpoch(1700000000500, isUtc: true));

      final push = challengeFromMessage(
            _message('push', '{"sent":true,"poll_interval":0,"user_verification":{"type":"number_match","number":"42"},"devices":[{"label":"Pixel"}]}'),
          )
          as PushChallenge;
      expect(push.pollInterval, 1);
      expect(push.userVerificationNumber, '42');
      expect(push.devices, ['Pixel']);
      expect(push.isPending, isTrue);

      final terms = challengeFromMessage(_message('terms', '{"url":"https://example.com/terms","version":"3"}', skippable: true)) as TermsChallenge;
      expect(terms.url, Uri.parse('https://example.com/terms'));
      expect(terms.isSkippable, isTrue);

      final username = challengeFromMessage(_message('username', '')) as UsernameChallenge;
      expect(username.allowEmail, isFalse);
      expect(username.params, isEmpty);
    });
  });

  group('answers', () {
    test('each answer maps to its kind and values', () {
      expect(answerToMessage(const ChallengeAnswer.username('alice')).value, 'alice');
      final totp = answerToMessage(const ChallengeAnswer.totp('123456', credentialId: 'a'));
      expect((totp.kind, totp.value, totp.credentialId), (AnswerKind.totp, '123456', 'a'));
      final update = answerToMessage(const ChallengeAnswer.updatePassword('n3w', confirm: 'n3w'));
      expect((update.kind, update.value, update.confirm), (AnswerKind.updatePassword, 'n3w', 'n3w'));
      expect(answerToMessage(const ChallengeAnswer.terms(accepted: true)).accepted, isTrue);
      final pin = answerToMessage(const ChallengeAnswer.pin('2580'));
      expect((pin.kind, pin.value), (AnswerKind.pin, '2580'));
      final pinSetup = answerToMessage(const ChallengeAnswer.pinSetup('2580', confirm: '2580'));
      expect((pinSetup.kind, pinSetup.value, pinSetup.confirm), (AnswerKind.pinSetup, '2580', '2580'));
      final skip = answerToMessage(const ChallengeAnswer.skip(ChallengeType.passkeyRegistration));
      expect((skip.kind, skip.type), (AnswerKind.skip, 'passkey_registration'));
      final custom = answerToMessage(const ChallengeAnswer.custom(ChallengeType.unknown('x_face_scan'), [('x_score', '0.9'), ('x_id', '7')]));
      expect(custom.type, 'x_face_scan');
      expect(custom.fields!.map((f) => (f.name, f.value)), [('x_score', '0.9'), ('x_id', '7')]);
      for (final (answer, kind) in [
        (const ChallengeAnswer.otpResend(), AnswerKind.otpResend),
        (const ChallengeAnswer.verifyEmailResend(), AnswerKind.verifyEmailResend),
        (const ChallengeAnswer.pushResend(), AnswerKind.pushResend),
        (const ChallengeAnswer.pushPoll(), AnswerKind.pushPoll),
        (const ChallengeAnswer.pushEnrollmentCheck(), AnswerKind.pushEnrollmentCheck),
      ]) {
        expect(answerToMessage(answer).kind, kind);
      }
    });

    test('an answer for another type is refused before it is sent', () async {
      final flow = NativeLoginFlow.internal(KeycloakNativeHostApi(), 'flow', isStepUp: false);
      final password = challengeFromMessage(_message('password', '{}'));
      expect(() => flow.respond(const ChallengeAnswer.username('alice'), password), throwsA(isA<NativeAuthException>()));
    });

    test('secrets are not printed', () {
      expect(const ChallengeAnswer.password('hunter2').toString(), isNot(contains('hunter2')));
      expect(const ChallengeAnswer.pin('2580').toString(), isNot(contains('2580')));
      expect(const ChallengeAnswer.pinSetup('2580', confirm: '2580').toString(), isNot(contains('2580')));
    });
  });

  test('credentials keep the handle until stored and never print tokens', () {
    final credentials = credentialsFromMessage(
      CredentialsMessage(handle: 'h', accessToken: 'at', tokenType: 'DPoP', expiresAtMillis: 0, issuedAtMillis: 0, hasRefreshToken: true),
    );
    expect(credentials.handle, 'h');
    expect(credentials.isDPoPBound, isTrue);
    expect(credentials.isExpired(), isTrue);
    expect(credentials.toString(), isNot(contains('at,')));
    final stored = credentialsFromMessage(
      CredentialsMessage(handle: '', accessToken: 'at', tokenType: 'Bearer', expiresAtMillis: 0, issuedAtMillis: 0, hasRefreshToken: false),
    );
    expect(stored.handle, isNull);
  });

  test('a PlatformException from the bridge becomes a NativeAuthException', () {
    final error = NativeAuthException.fromPlatformException(
      PlatformException(
        code: 'insufficient_authorization',
        message: 'Step up',
        details: {'statusCode': 403, 'isNetworkError': false, 'isRetryable': false, 'maxAge': 300, 'detailsJson': '{"max_age":300}'},
      ),
    );
    expect(error.code, NativeAuthErrorCode.insufficientAuthorization);
    expect(error.statusCode, 403);
    expect(error.maxAge, 300);
    expect(error.details?['max_age'], 300);
  });
}
