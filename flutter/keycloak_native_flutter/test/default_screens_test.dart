// Every default screen over a recorded transcript (spec/18 §7): the widgets, the controller and the
// ceremonies' routing against what the server recorded.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native_flutter/keycloak_native_flutter.dart';

import 'support/transcript_host.dart';

class _Login {
  _Login(this.tester, this.host, this.results);

  final WidgetTester tester;
  final TranscriptHostApi host;
  final List<NativeLoginResult> results;

  Future<void> type(String key, String text) async {
    await tester.enterText(find.byKey(ValueKey(key)), text);
    await tester.pump();
  }

  Future<void> tap(Finder finder) async {
    await tester.ensureVisible(finder);
    await tester.tap(finder);
    await tester.pumpAndSettle();
  }

  Future<void> tapKey(String key) => tap(find.byKey(ValueKey(key)));
  Future<void> tapText(String text) => tap(find.text(text));

  /// The view keeps a progress indicator once finished, so the last step pumps instead of settling.
  Future<void> tapLast(Finder finder) async {
    await tester.ensureVisible(finder);
    await tester.tap(finder);
    for (var i = 0; i < 5; i++) {
      await tester.pump();
    }
  }

  Future<void> signIn(String username) async {
    await type('username', username);
    await tapText('Continue');
    await type('password', 'secret');
    await tap(find.widgetWithText(FilledButton, 'Sign in'));
  }
}

Future<_Login> _pump(
  WidgetTester tester,
  String transcript, {
  required String clientId,
  NativeLoginStrings? strings,
  bool autoSelectPasskey = false,
  SavedPasswordMessageFactory? saved,
}) async {
  final host = TranscriptHostApi(loadTranscript(transcript));
  if (saved != null) host.savedPassword = saved();
  late KeycloakNative kc;
  late NativeLoginFlow flow;
  await tester.runAsync(() async {
    kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: clientId, hostApi: host);
    flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'NativeAuthIT'));
  });
  final results = <NativeLoginResult>[];
  await tester.binding.setSurfaceSize(const Size(800, 1400));
  await tester.pumpWidget(
    MaterialApp(
      home: Scaffold(body: NativeLoginView(kc: kc, flow: flow, onResult: results.add, autoSelectPasskey: autoSelectPasskey, strings: strings)),
    ),
  );
  await tester.pumpAndSettle();
  return _Login(tester, host, results);
}

typedef SavedPasswordMessageFactory = dynamic Function();

void main() {
  testWidgets('otp: the code is sent on request, then verified', (tester) async {
    final login = await _pump(tester, 'OtpIT.aliceChoosesBetweenTotpAndEmailAndTheCodeIsOnlySentOnRequest', clientId: 'demo-native-otp');
    await login.signIn('alice');
    expect(find.text('Authenticator code'), findsOneWidget);
    await login.tapKey('switchTo-otp');
    expect(find.text('Email code'), findsOneWidget);
    await login.tapKey('otpSend');
    expect(find.byKey(const ValueKey('otp')), findsOneWidget);
    await login.type('otp', '123456');
    await login.tapLast(find.text('Verify'));
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('recovery_code: a wrong code shows the descriptor error, the next one signs in', (tester) async {
    final login = await _pump(tester, 'RecoveryCodeIT.ivyUsesRecoveryCodesUntilTheyRunOut', clientId: 'demo-native');
    await login.signIn('ivy');
    await login.tapKey('switchTo-recovery_code');
    expect(find.text('Recovery code'), findsOneWidget);
    await login.type('recoveryCode', 'AAAA-BBBB-CCCC');
    await login.tap(find.widgetWithText(FilledButton, 'Sign in'));
    expect(find.byKey(const ValueKey('challengeError')), findsOneWidget);
    await login.type('recoveryCode', 'DDDD-EEEE-FFFF');
    await login.tapLast(find.widgetWithText(FilledButton, 'Sign in'));
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('update_password: errors stay on the screen until the policy accepts the password', (tester) async {
    final login = await _pump(tester, 'RequiredActionsIT.carolUpdatesHerPasswordInBand', clientId: 'demo-native');
    await login.signIn('carol');
    expect(find.text('Choose a new password'), findsOneWidget);
    // The button stays off until both fields match.
    await login.type('newPassword', 'one');
    await login.type('newPasswordConfirm', 'two');
    expect(find.text('Passwords do not match'), findsOneWidget);
    for (var attempt = 0; attempt < 3; attempt++) {
      await login.type('newPassword', 'n3w-Passw0rd');
      await login.type('newPasswordConfirm', 'n3w-Passw0rd');
      await login.tapKey('updatePassword');
      expect(find.byKey(const ValueKey('challengeError')), findsOneWidget);
    }
    await login.type('newPassword', 'n3w-Passw0rd');
    await login.type('newPasswordConfirm', 'n3w-Passw0rd');
    await login.tapLast(find.byKey(const ValueKey('updatePassword')));
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('verify_email: resend too soon, a wrong code, the right one', (tester) async {
    final login = await _pump(tester, 'RequiredActionsIT.graceVerifiesHerEmailWithACode', clientId: 'demo-native');
    await login.signIn('grace');
    expect(find.text('Verify your email'), findsOneWidget);
    await login.tapKey('verifyEmailResend');
    expect(find.byKey(const ValueKey('challengeError')), findsOneWidget);
    await login.type('verifyEmailCode', '000000');
    await login.tapText('Verify');
    await login.type('verifyEmailCode', '123456');
    await login.tapLast(find.text('Verify'));
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('terms: accepting continues', (tester) async {
    final host = TranscriptHostApi(loadTranscript('RequiredActionsIT.hankMustAcceptTheTermsAndDecliningEndsTheLogin'))..skipTo(5);
    late KeycloakNative kc;
    late NativeLoginFlow flow;
    await tester.runAsync(() async {
      kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: 'demo-native', hostApi: host);
      flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'NativeAuthIT'));
    });
    final results = <NativeLoginResult>[];
    await tester.binding.setSurfaceSize(const Size(800, 1400));
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: NativeLoginView(kc: kc, flow: flow, onResult: results.add))));
    await tester.pumpAndSettle();
    final login = _Login(tester, host, results);
    await login.signIn('hank');
    expect(find.text('Terms and conditions'), findsOneWidget);
    await login.tapLast(find.byKey(const ValueKey('acceptTerms')));
    expect(results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('push_enrollment: enrolls through the native ceremony, retrying after an error', (tester) async {
    final login = await _pump(tester, 'PushMfaIT.judyEnrolsMidFlowThroughTheNativeRequiredAction', clientId: 'demo-native');
    await login.signIn('judy');
    expect(find.text('Set up sign-in approvals'), findsOneWidget);
    await login.tapKey('pushEnroll');
    expect(find.byKey(const ValueKey('challengeError')), findsOneWidget);
    await login.type('pushDeviceLabel', 'Judy Pixel');
    await login.tapLast(find.byKey(const ValueKey('pushEnroll')));
    expect(login.host.calls, ['enrollPush:This device:none', 'enrollPush:Judy Pixel:none']);
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('passkey: a discoverable passkey first, then the second factor', (tester) async {
    final login = await _pump(tester, 'PasskeyIT.discoverableLoginWithUserHandle', clientId: 'demo-native-passkey');
    expect(find.text('Sign in with a passkey'), findsOneWidget);
    expect(find.byKey(const ValueKey('switchTo-username')), findsOneWidget);
    await login.tapKey('usePasskey');
    expect(find.text('Authenticator code'), findsOneWidget);
    await login.type('totp', '123456');
    await login.tapLast(find.text('Verify'));
    expect(login.host.calls, ['usePasskey']);
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('autoSelectPasskey runs the ceremony without a tap', (tester) async {
    final login = await _pump(tester, 'PasskeyIT.discoverableLoginWithUserHandle', clientId: 'demo-native-passkey', autoSelectPasskey: true);
    expect(login.host.calls, ['usePasskey']);
    expect(find.text('Authenticator code'), findsOneWidget);
  });

  testWidgets('passkey_registration: "Not now" declines an optional enrollment', (tester) async {
    final login = await _pump(tester, 'EnrolOnFirstLoginIT.bobMayDeclineAnOptionalEnrolmentAndIsOfferedItAgainAtTheNextLogin', clientId: 'demo-native');
    await login.signIn('bob');
    expect(find.text('Create a passkey'), findsOneWidget);
    await login.tapLast(find.byKey(const ValueKey('skipChallenge')));
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('passkey_registration: creates the passkey with its label', (tester) async {
    final login = await _pump(tester, 'EnrolOnFirstLoginIT.bobEnrolsAPasskeyRightAfterHisFirstPasswordLogin', clientId: 'demo-native');
    await login.signIn('bob');
    await login.type('passkeyLabel', 'Bob phone');
    await login.tapLast(find.byKey(const ValueKey('createPasskey')));
    expect(login.host.calls, ['registerPasskey:Bob phone']);
    expect(login.results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('push: the request is sent on demand and the number shown', (tester) async {
    final login = await _pump(tester, 'PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch', clientId: 'demo-native');
    await login.signIn('alice');
    await login.tapKey('switchTo-push');
    expect(find.text('Approve on your phone'), findsWidgets);
    // The waiting indicator spins and the screen polls, so this pumps instead of settling.
    await tester.tap(find.byKey(const ValueKey('pushSend')));
    for (var i = 0; i < 5; i++) {
      await tester.pump();
    }
    expect(find.byKey(const ValueKey('pushNumber')), findsOneWidget);
    expect(find.byKey(const ValueKey('pushWaiting')), findsOneWidget);
    // The screen polls at poll_interval (3 s).
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();
    expect(login.host.consumed, 5);
    // Leave the screen before the next poll: the rest of the transcript is the phone's part.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('a saved password answers username and password, a typed one is offered for saving', (tester) async {
    final login = await _pump(
      tester,
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri',
      clientId: 'demo-native',
      saved: () => null,
    );
    // Without a saved password the sheet is "cancelled": the screen stays.
    await login.tapKey('useSavedPassword');
    expect(find.text('Sign in'), findsWidgets);
    await login.signIn('alice');
    await login.type('totp', '123456');
    await login.tapLast(find.text('Verify'));
    expect(login.results.single, isA<NativeLoginAuthorized>());
    expect(login.host.savedPasswords, [('alice', 'secret')]);
  });

  testWidgets('German texts for a German locale', (tester) async {
    expect(NativeLoginStrings.forLocale(const Locale('de', 'AT')), isA<NativeLoginStringsDe>());
    expect(NativeLoginStrings.forLocale(const Locale('fr')).runtimeType, NativeLoginStrings);
    expect(const NativeLoginStringsDe().passwordPolicyHints({'length': 8, 'digits': 1}), ['Mindestens 8 Zeichen', 'Mindestens 1 Ziffer']);
    expect(const NativeLoginStrings().passwordPolicyHints({'length': 8, 'upperCase': 2, 'notUsername': true}), [
      'At least 8 characters',
      'At least 2 upper-case letters',
      'Not your username',
    ]);
    await _pump(
      tester,
      'NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri',
      clientId: 'demo-native',
      strings: NativeLoginStrings.forLocale(const Locale('de')),
    );
    expect(find.text('Anmelden'), findsOneWidget);
    expect(find.text('Weiter'), findsOneWidget);
  });

  testWidgets('PushApprovalsView: a wrong number keeps the card, the right one approves', (tester) async {
    final host = TranscriptHostApi(loadTranscript('PushMfaIT.scenarioB_aNativeLoginOffersPushWithNumberMatch'))..skipTo(6);
    late KeycloakNative kc;
    await tester.runAsync(() async {
      kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: 'demo-native', hostApi: host);
    });
    final responded = <String>[];
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: PushApprovalsView(
            push: kc.push,
            onResponded: (a, status) => responded.add(status),
            // The recorded approval expired long ago.
            clock: () => DateTime.utc(2026, 11, 6, 20, 42),
          ))));
    await tester.pumpAndSettle();
    expect(find.text('Sign-in to Demo iOS App'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('pushNumber-31')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('pushApprovalsMessage')), findsOneWidget);
    expect(find.byKey(const ValueKey('pushNumber-52')), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('pushNumber-52')));
    await tester.pumpAndSettle();
    expect(responded, ['approved']);
    expect(find.byKey(const ValueKey('pushNoApprovals')), findsOneWidget);
    expect(host.calls, ['pushRespond:ea41f0c2-df24-435d-a4b9-6be18c2e7085:true:31', 'pushRespond:ea41f0c2-df24-435d-a4b9-6be18c2e7085:true:52']);
  });
}
