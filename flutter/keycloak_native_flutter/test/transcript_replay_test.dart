// Drives the Dart layer through recorded server transcripts (spec/18 §7): the twin of the native
// SDKs' TranscriptReplay suites, one level up. See support/transcript_host.dart for what is compared.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';
import 'package:keycloak_native_flutter/src/mapping.dart';
import 'package:keycloak_native_flutter/src/messages.g.dart';

import 'support/transcript_host.dart';

/// The client id and parameters of the transcript's first request, as the test app would set them.
(String, LoginParameters) _initialRequest(Map<String, Object?> transcript, {int exchange = 0}) {
  final form = ((((transcript['exchanges'] as List)[exchange] as Map)['request'] as Map)['form'] as Map).cast<String, String>();
  return (
    form['client_id']!,
    LoginParameters(scope: form['scope'], deviceName: form['device_name'], acrValues: form['acr_values'], maxAge: int.tryParse(form['max_age'] ?? '')),
  );
}

Future<(KeycloakNative, NativeLoginFlow, TranscriptHostApi)> _begin(String name) async {
  final transcript = loadTranscript(name);
  final host = TranscriptHostApi(transcript);
  final (clientId, parameters) = _initialRequest(transcript);
  final kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: clientId, hostApi: host);
  return (kc, await kc.authentication.startLogin(parameters), host);
}

void main() {
  test('happy path: username, password, TOTP, then tokens', () async {
    final (kc, flow, host) = await _begin('NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri');

    var step = await flow.start() as ChallengesStep;
    final username = step.challenges.single as UsernameChallenge;
    expect(username.allowEmail, isTrue);
    expect(step.context.clientName, isNotNull);

    step = await flow.respond(const ChallengeAnswer.username('alice'), username) as ChallengesStep;
    final password = step.challenges.single as PasswordChallenge;
    expect(password.usernameKnown, isTrue);
    expect(step.context.username, 'alice');
    expect(step.context.displayName, 'Alice Example');

    step = await flow.respond(const ChallengeAnswer.password('secret'), password) as ChallengesStep;
    final totp = step.challenges.single as TotpChallenge;
    expect(totp.digits, 6);
    expect(totp.period, 30);

    final authorized = await flow.respond(const ChallengeAnswer.totp('123456'), totp) as AuthorizedStep;
    final credentials = authorized.credentials;
    expect(credentials.tokenType, 'Bearer');
    expect(credentials.hasRefreshToken, isTrue);
    expect(credentials.idTokenClaims?['preferred_username'], 'alice');
    expect(credentials.isExpired(), isFalse);

    await kc.credentialsManager.store(credentials);
    expect(host.stored, [credentials.handle]);
    await flow.dispose();
    expect(host.flowsDisposed, 1);
  });

  test('a wrong password comes back as a descriptor error, then succeeds', () async {
    final (_, flow, _) = await _begin('NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds');
    var step = await flow.start() as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.username('alice'), step.challenges.single) as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.password('wrong'), step.challenges.single) as ChallengesStep;
    final retried = step.challenges.single as PasswordChallenge;
    expect(retried.error?.code, ChallengeError.invalidCredential);
    expect(retried.retryRemaining, isNotNull);
    step = await flow.respond(const ChallengeAnswer.password('right'), retried) as ChallengesStep;
    expect(step.challenges.single, isA<TotpChallenge>());
  });

  test('alternatives arrive together and either one can be answered', () async {
    final (_, flow, _) = await _begin('NativeAuthIT.q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered');
    var step = await flow.start() as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.username('alice'), step.challenges.single) as ChallengesStep;
    expect(step.challenges.map((c) => c.type), [ChallengeType.password, ChallengeType.totp]);
    final totp = step.challenges[1] as TotpChallenge;
    expect(totp.credentials.single.label, 'Phone');
    expect(await flow.respond(const ChallengeAnswer.totp('123456'), totp), isA<AuthorizedStep>());
  });

  test('a form authenticator the realm sends to the web becomes RedirectToWebStep', () async {
    final (kc, flow, _) = await _begin('NonNativeExecutionIT.aFormAuthenticatorRedirectsToWebWhenTheRealmSaysSo');
    final step = await flow.start() as RedirectToWebStep;
    expect(step.request.redirectUri, 'demoapp://auth/callback');
    expect(step.request.reason, 'execution:auth-username-password-form');
    expect(step.request.state, isNotNull);
    // The fake's browser is closed by the user.
    await expectLater(
      kc.webFallback.complete(flow),
      throwsA(isA<NativeAuthException>().having((e) => e.code, 'code', NativeAuthErrorCode.webFallbackCancelled)),
    );
  });

  test('declining the terms ends the login with access_denied', () async {
    final (_, flow, _) = await _begin('RequiredActionsIT.hankMustAcceptTheTermsAndDecliningEndsTheLogin');
    var step = await flow.start() as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.username('hank'), step.challenges.single) as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.password('secret'), step.challenges.single) as ChallengesStep;
    final terms = step.challenges.single as TermsChallenge;
    expect(terms.type.isRequiredAction, isTrue);
    expect(terms.text ?? terms.url?.toString(), isNotNull);
    await expectLater(
      flow.respond(const ChallengeAnswer.terms(accepted: false), terms),
      throwsA(isA<NativeAuthException>().having((e) => e.code, 'code', NativeAuthErrorCode.accessDenied).having((e) => e.statusCode, 'status', 403)),
    );
  });

  // PinIT's recordings on demo-native-pin: pia has a PIN, pete sets one, rita's locks after 3 attempts.
  test('pin: a wrong PIN, then the right one', () async {
    final (_, flow, _) = await _begin('PinIT.piaSignsInWithHerPinAfterAWrongOne');
    var step = await flow.start() as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.username('pia'), step.challenges.single) as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.password('secret'), step.challenges.single) as ChallengesStep;
    final pin = step.challenges.single as PinChallenge;
    expect(pin.length, 4);
    expect(pin.type.isRequiredAction, isFalse);
    step = await flow.respond(const ChallengeAnswer.pin('0000'), pin) as ChallengesStep;
    final retried = step.challenges.single as PinChallenge;
    expect(retried.error?.code, ChallengeError.invalidCredential);
    expect(retried.retryRemaining, 2);
    expect(retried.isLocked, isFalse);
    expect(await flow.respond(const ChallengeAnswer.pin('2580'), retried), isA<AuthorizedStep>());
  });

  test('pin_setup: missing_credential, pin_mismatch, weak_pin and invalid_format, then the PIN is set', () async {
    final (_, flow, _) = await _begin('PinIT.peteSetsAPinInBand');
    var step = await flow.start() as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.username('pete'), step.challenges.single) as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.password('secret'), step.challenges.single) as ChallengesStep;
    var setup = step.challenges.single as PinSetupChallenge;
    expect(setup.type.isRequiredAction, isTrue);
    expect(setup.length, 4);
    expect(setup.isWellFormed('2580'), isTrue);
    expect(setup.isWellFormed('258'), isFalse);
    expect(setup.isWellFormed('25a0'), isFalse);
    final errors = <String?>[];
    for (final (pin, confirm) in [('', ''), ('1357', '1358'), ('1111', '1111'), ('12', '12')]) {
      step = await flow.respond(ChallengeAnswer.pinSetup(pin, confirm: confirm), setup) as ChallengesStep;
      setup = step.challenges.single as PinSetupChallenge;
      errors.add(setup.error?.code);
    }
    expect(errors, [ChallengeError.missingCredential, ChallengeError.pinMismatch, ChallengeError.weakPin, ChallengeError.invalidFormat]);
    expect(await flow.respond(const ChallengeAnswer.pinSetup('2580', confirm: '2580'), setup), isA<AuthorizedStep>());
  });

  test('pin: credential_locked marks the challenge locked with no attempts left', () async {
    final (_, flow, _) = await _begin('PinIT.aLockedPinCanOnlyBeCancelled');
    var step = await flow.start() as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.username('rita'), step.challenges.single) as ChallengesStep;
    step = await flow.respond(const ChallengeAnswer.password('secret'), step.challenges.single) as ChallengesStep;
    for (final (pin, remaining) in [('0001', 2), ('0002', 1)]) {
      step = await flow.respond(ChallengeAnswer.pin(pin), step.challenges.single) as ChallengesStep;
      expect((step.challenges.single as PinChallenge).retryRemaining, remaining);
    }
    step = await flow.respond(const ChallengeAnswer.pin('0009'), step.challenges.single) as ChallengesStep;
    final locked = step.challenges.single as PinChallenge;
    expect(locked.isLocked, isTrue);
    expect(locked.error?.code, ChallengeError.credentialLocked);
    expect(locked.retryRemaining, 0);
  });

  test('a request the native SDK would not send fails the replay', () async {
    final (_, flow, _) = await _begin('NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri');
    final step = await flow.start() as ChallengesStep;
    // The transcript answered with "alice".
    await expectLater(flow.respond(const ChallengeAnswer.username('bob'), step.challenges.single), throwsA(isA<TranscriptMismatch>()));
  });

  test('NativeLoginController drives username, password and TOTP to Authorized', () async {
    final (kc, flow, _) = await _begin('NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri');
    final results = <NativeLoginResult>[];
    final controller = NativeLoginController(kc: kc, flow: flow, onResult: results.add)..start();
    Future<NativeLoginChallenges> settled() async {
      while (controller.isSubmitting) {
        await Future<void>.delayed(Duration.zero);
      }
      return controller.phase as NativeLoginChallenges;
    }

    var phase = await settled();
    controller.submit(const ChallengeAnswer.username('alice'), phase.selected);
    phase = await settled();
    expect(phase.selected, isA<PasswordChallenge>());
    controller.submit(const ChallengeAnswer.password('secret'), phase.selected);
    phase = await settled();
    controller.submit(const ChallengeAnswer.totp('123456'), phase.selected);
    while (results.isEmpty) {
      await Future<void>.delayed(Duration.zero);
    }
    expect(results.single, isA<NativeLoginAuthorized>());
    expect(controller.phase, isA<NativeLoginFinished>());
  });

  // Every descriptor the server has ever been recorded sending maps to a typed Dart challenge, and
  // every typed getter reads it without throwing. A new challenge type or a params shape the Dart
  // model cannot read fails here.
  test('every recorded challenge descriptor maps to its typed class', () {
    final seen = <String>{};
    for (final file in allTranscripts()) {
      final transcript = (jsonDecode(file.readAsStringSync()) as Map).cast<String, Object?>();
      for (final exchange in transcript['exchanges'] as List) {
        // The push device API's /login/pending lists ba-itsys challenges, not descriptors.
        if (!(((exchange as Map)['request'] as Map)['path'] as String).endsWith('/native-auth/challenge')) continue;
        final json = (exchange['response'] as Map)['json'];
        if (json is! Map || json['challenges'] is! List) continue;
        for (final descriptor in json['challenges'] as List) {
          final d = (descriptor as Map).cast<String, Object?>();
          final challenge = challengeFromMessage(
            ChallengeMessage(
              id: d['id'] as String,
              type: d['type'] as String,
              required: d['required'] as bool? ?? true,
              skippable: d['skippable'] as bool? ?? false,
              paramsJson: jsonEncode(d['params'] ?? const {}),
            ),
          );
          seen.add(challenge.type.wire);
          expect(challenge, isNot(isA<UnknownChallenge>()), reason: '${file.path}: ${d['type']}');
          _readEveryGetter(challenge);
        }
      }
    }
    expect(seen, containsAll(['username', 'password', 'totp', 'otp', 'passkey', 'push', 'recovery_code', 'update_password', 'verify_email', 'terms']));
  });
}

void _readEveryGetter(Challenge challenge) {
  switch (challenge) {
    case UsernameChallenge c:
      [c.allowEmail, c.hint];
    case PasswordChallenge c:
      c.usernameKnown;
    case TotpChallenge c:
      [c.digits, c.period, c.algorithm, c.credentials];
    case OtpChallenge c:
      [c.channel, c.destinationMasked, c.digits, c.ttl, c.sent, c.resendAllowedAt];
      expect(c.channel, anyOf('email', 'sms'));
    case PasskeyChallenge c:
      [c.rpId, c.userVerification, c.discoverable];
      expect(c.rpId, isNotNull);
    case PasskeyRegistrationChallenge c:
      [c.rpId, c.rpName, c.userName, c.userDisplayName];
      expect(c.userName, isNotNull);
    case PushChallenge c:
      [c.sent, c.expiresAt, c.pollInterval, c.status, c.userVerificationNumber, c.devices, c.resendAllowedAt, c.isPending];
    case PushEnrollmentChallenge c:
      [c.expiresIn, c.userId];
    case RecoveryCodeChallenge c:
      [c.remaining, c.warningThreshold, c.shouldWarn];
    case UpdatePasswordChallenge c:
      [c.username, c.policy, c.minimumLength, c.maximumLength];
    case VerifyEmailChallenge c:
      [c.emailMasked, c.digits, c.ttl, c.sent, c.resendAllowedAt];
    case TermsChallenge c:
      [c.text, c.url, c.version];
    case PinChallenge c:
      [c.length, c.isLocked];
    case PinSetupChallenge c:
      [c.length, c.isWellFormed('0000')];
    case UnknownChallenge():
      break;
  }
}
