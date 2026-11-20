// Application-initiated actions (spec/21), replayed from the transcripts of KcActionIT: the Dart twin
// of the native KcActionReplay suites.
import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';

import 'support/transcript_host.dart';

/// Application-initiated actions (spec/21): `Authentication.requiredAction` is a step-up with
/// `kc_action`; `AuthorizedStep.kcActionStatus` reports the outcome. Twin of the native
/// KcActionReplay suites, from the transcripts of KcActionIT.
Future<KeycloakNative> _signedIn(TranscriptHostApi host, {int skipTo = 1}) async {
  host.skipTo(skipTo);
  final kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: 'demo-native', hostApi: host);
  final flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'NativeAuthIT'));
  var step = await flow.start() as ChallengesStep;
  step = await flow.respond(const ChallengeAnswer.username('alice'), step.challenges.single) as ChallengesStep;
  step = await flow.respond(const ChallengeAnswer.password('alice-password'), step.challenges.whereType<PasswordChallenge>().single) as ChallengesStep;
  final authorized = await flow.respond(const ChallengeAnswer.totp('000000'), step.challenges.whereType<TotpChallenge>().single) as AuthorizedStep;
  expect(authorized.kcActionStatus, isNull, reason: 'a login without kc_action has no status');
  await kc.credentialsManager.store(authorized.credentials);
  return kc;
}

void main() {
  group('requiredAction (spec/21)', () {
    test('changes the password right after signing in and signs out other devices', () async {
      final host = TranscriptHostApi(loadTranscript('KcActionIT.aliceChangesHerPasswordRightAfterSigningInAndHerOtherSessionsEnd'));
      final kc = await _signedIn(host, skipTo: 6); // 1–5 are the other device
      final flow = await kc.authentication.requiredAction('UPDATE_PASSWORD', scope: 'openid profile', deviceName: 'NativeAuthIT');
      final step = await flow.start() as ChallengesStep;
      final update = step.challenges.single as UpdatePasswordChallenge;
      expect(update.isSkippable, isTrue);
      expect(update.logoutOtherSessions, isTrue);
      final authorized = await flow.respond(
        const ChallengeAnswer.updatePassword('alice-new-password', confirm: 'alice-new-password', logoutOtherSessions: true),
        update,
      ) as AuthorizedStep;
      expect(authorized.kcActionStatus, KcActionStatus.success);
    });

    test('max_age=0 re-authenticates; cancelling reports cancelled', () async {
      final host = TranscriptHostApi(loadTranscript('KcActionIT.maxAgeZeroReauthenticatesAndCancellingKeepsThePassword'));
      final kc = await _signedIn(host);
      final flow = await kc.authentication.requiredAction('UPDATE_PASSWORD', maxAge: 0, scope: 'openid profile', deviceName: 'NativeAuthIT');
      var step = await flow.start() as ChallengesStep;
      step = await flow.respond(const ChallengeAnswer.password('alice-password'), step.challenges.whereType<PasswordChallenge>().single) as ChallengesStep;
      step = await flow.respond(const ChallengeAnswer.totp('000000'), step.challenges.whereType<TotpChallenge>().single) as ChallengesStep;
      final update = step.challenges.single as UpdatePasswordChallenge;
      final authorized = await flow.respond(ChallengeAnswer.skip(update.type), update) as AuthorizedStep;
      expect(authorized.kcActionStatus, KcActionStatus.cancelled);
    });

    test('an action that cannot be initiated reports error', () async {
      final host = TranscriptHostApi(loadTranscript('KcActionIT.anActionThatCannotBeInitiatedReportsError'));
      final kc = await _signedIn(host);
      for (final action in ['TERMS_AND_CONDITIONS', 'no-such-action']) {
        final flow = await kc.authentication.requiredAction(action, scope: 'openid profile', deviceName: 'NativeAuthIT');
        final authorized = await flow.start() as AuthorizedStep;
        expect(authorized.kcActionStatus, KcActionStatus.error, reason: action);
        await kc.credentialsManager.store(authorized.credentials);
      }
    });

    test('KcActionStatus keeps unknown values', () {
      expect(KcActionStatus.fromWire('later').wire, 'later');
      expect(KcActionStatus.fromWire('success'), same(KcActionStatus.success));
    });
  });
}
