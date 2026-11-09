// The default widgets over a recorded transcript: type into the username, password and TOTP screens
// and get NativeLoginAuthorized.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native/keycloak_native.dart';

import 'support/transcript_host.dart';

void main() {
  testWidgets('username, password and TOTP screens complete the login', (tester) async {
    final host = TranscriptHostApi(loadTranscript('NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'));
    late KeycloakNative kc;
    late NativeLoginFlow flow;
    await tester.runAsync(() async {
      kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: 'demo-native', hostApi: host);
      flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'NativeAuthIT'));
    });
    final results = <NativeLoginResult>[];
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: NativeLoginView(kc: kc, flow: flow, onResult: results.add))));
    await tester.pumpAndSettle();

    expect(find.text('Sign in'), findsOneWidget);
    await tester.enterText(find.byKey(const ValueKey('username')), 'alice');
    await tester.pump();
    await tester.tap(find.text('Continue'));
    await tester.pumpAndSettle();

    expect(find.text('Enter your password'), findsOneWidget);
    expect(find.text('Signing in as Alice Example'), findsOneWidget);
    // The username is repeated read-only for password managers.
    expect(find.byKey(const ValueKey('autofillUsername')), findsOneWidget);
    await tester.enterText(find.byKey(const ValueKey('password')), 'secret');
    await tester.pump();
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await tester.pumpAndSettle();

    expect(find.text('Authenticator code'), findsOneWidget);
    await tester.enterText(find.byKey(const ValueKey('totp')), '123456');
    await tester.pump();
    await tester.tap(find.text('Verify'));
    // The finished view shows a progress indicator until the app replaces it, so it never settles.
    await tester.pump();

    expect(results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('alternatives are offered under the screen and switch it', (tester) async {
    final host = TranscriptHostApi(loadTranscript('NativeAuthIT.q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered'));
    late KeycloakNative kc;
    late NativeLoginFlow flow;
    await tester.runAsync(() async {
      kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: 'demo-native-alt', hostApi: host);
      flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'NativeAuthIT'));
    });
    final results = <NativeLoginResult>[];
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: NativeLoginView(kc: kc, flow: flow, onResult: results.add))));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('username')), 'alice');
    await tester.pump();
    await tester.tap(find.text('Continue'));
    await tester.pumpAndSettle();

    expect(find.text('Enter your password'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('switchTo-totp')));
    await tester.pumpAndSettle();
    expect(find.text('Authenticator code'), findsOneWidget);
    await tester.enterText(find.byKey(const ValueKey('totp')), '123456');
    await tester.pump();
    await tester.tap(find.text('Verify'));
    // The finished view shows a progress indicator until the app replaces it, so it never settles.
    await tester.pump();
    expect(results.single, isA<NativeLoginAuthorized>());
  });

  testWidgets('a type without a default screen uses the app presenter', (tester) async {
    final host = TranscriptHostApi(loadTranscript('RequiredActionsIT.hankMustAcceptTheTermsAndDecliningEndsTheLogin'));
    late KeycloakNative kc;
    late NativeLoginFlow flow;
    await tester.runAsync(() async {
      kc = await KeycloakNative.configure(issuer: Uri.parse('http://localhost/realms/demo'), clientId: 'demo-native', hostApi: host);
      flow = await kc.authentication.startLogin(const LoginParameters(scope: 'openid profile', deviceName: 'NativeAuthIT'));
    });
    final results = <NativeLoginResult>[];
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: NativeLoginView(
            kc: kc,
            flow: flow,
            onResult: results.add,
            presenters: {
              ChallengeType.terms: (context, p) => TextButton(onPressed: () => p.submit(const ChallengeAnswer.terms(accepted: false)), child: const Text('Decline terms')),
            },
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('username')), 'hank');
    await tester.pump();
    await tester.tap(find.text('Continue'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('password')), 'secret');
    await tester.pump();
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Decline terms'));
    // The finished view shows a progress indicator until the app replaces it, so it never settles.
    await tester.pump();
    expect(results.single, isA<NativeLoginFailed>().having((r) => r.error.code, 'code', NativeAuthErrorCode.accessDenied));
  });
}
