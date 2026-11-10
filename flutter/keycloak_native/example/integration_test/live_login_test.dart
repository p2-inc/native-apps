// Signs in to the running demo stack (keycloak-native-auth/demo, `docker compose up`) through the
// real plugin and native SDK: username, password and TOTP for alice, then refresh and logout.
//
//   flutter test integration_test -d <simulator or emulator>
//   (Android emulator: the default issuer is http://10.0.2.2:8080/realms/demo)
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:keycloak_native_example/main.dart' as app;

/// RFC 6238 (SHA-1, 6 digits, 30 s) over the raw secret the demo realm seeds for alice.
String totp(String secret, DateTime now) {
  final counter = now.millisecondsSinceEpoch ~/ 1000 ~/ 30;
  final message = ByteData(8)..setInt64(0, counter);
  final hmac = Hmac(sha1, secret.codeUnits).convert(message.buffer.asUint8List()).bytes;
  final offset = hmac.last & 0x0f;
  final value = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return (value % 1000000).toString().padLeft(6, '0');
}

Future<void> waitFor(WidgetTester tester, Finder finder, {Duration timeout = const Duration(seconds: 30)}) async {
  final end = DateTime.now().add(timeout);
  while (finder.evaluate().isEmpty) {
    if (DateTime.now().isAfter(end)) throw TestFailure('Timed out waiting for $finder');
    await tester.pump(const Duration(milliseconds: 200));
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('alice signs in with username, password and TOTP', (tester) async {
    app.main();
    await waitFor(tester, find.text('Sign in').hitTestable());
    // A previous run may have left a session: log out first.
    if (find.text('Log out').evaluate().isNotEmpty) {
      await tester.tap(find.text('Log out'));
      await waitFor(tester, find.widgetWithText(FilledButton, 'Sign in'));
    }
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await waitFor(tester, find.byKey(const ValueKey('username')));

    await tester.enterText(find.byKey(const ValueKey('username')), 'alice');
    await tester.pump();
    await tester.tap(find.text('Continue'));
    await waitFor(tester, find.byKey(const ValueKey('password')));
    expect(find.text('Signing in as Alice Example'), findsOneWidget);

    await tester.enterText(find.byKey(const ValueKey('password')), 'alice-password');
    await tester.pump();
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await waitFor(tester, find.byKey(const ValueKey('totp')));

    await tester.enterText(find.byKey(const ValueKey('totp')), totp('alice-totp-secret-20261014', DateTime.now()));
    await tester.pump();
    await tester.tap(find.text('Verify'));
    await waitFor(tester, find.text('Signed in'));
    expect(find.text('User: alice'), findsOneWidget);

    await tester.tap(find.text('Refresh'));
    await tester.pump(const Duration(seconds: 2));
    expect(find.text('Signed in'), findsOneWidget);

    // Push MFA device side: in-app enrollment without delivery, the (empty) approvals list, forget.
    await tester.tap(find.text('Enroll for push'));
    await waitFor(tester, find.text('Push: enrolled as Flutter example'));
    await tester.tap(find.text('Sign-in requests'));
    await waitFor(tester, find.text('No sign-in requests are waiting.'));
    await tester.pageBack();
    await tester.pumpAndSettle();
    await tester.tap(find.text('Forget push enrollment'));
    await waitFor(tester, find.text('Push: not enrolled'));

    await tester.tap(find.text('Log out'));
    await waitFor(tester, find.widgetWithText(FilledButton, 'Sign in'));
  });

  testWidgets('bob signs in with an email code (OTP client, code read from mailpit)', (tester) async {
    final started = DateTime.now().toUtc();
    app.main();
    await waitFor(tester, find.byKey(const ValueKey('client')));
    await tester.tap(find.byKey(const ValueKey('client')));
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('demo-native-otp').last);
    await tester.pumpAndSettle();
    await waitFor(tester, find.widgetWithText(FilledButton, 'Sign in'));
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await waitFor(tester, find.byKey(const ValueKey('username')));
    await tester.enterText(find.byKey(const ValueKey('username')), 'bob');
    await tester.pump();
    await tester.tap(find.text('Continue'));
    await waitFor(tester, find.byKey(const ValueKey('password')));
    await tester.enterText(find.byKey(const ValueKey('password')), 'bob-password');
    await tester.pump();
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    // bob's only second factor: the server sends the code right away.
    await waitFor(tester, find.byKey(const ValueKey('otp')));
    await tester.enterText(find.byKey(const ValueKey('otp')), await mailpitCode(after: started));
    await tester.pump();
    await tester.tap(find.text('Verify'));
    await waitFor(tester, find.text('Signed in'));
    expect(find.text('User: bob'), findsOneWidget);
    await tester.tap(find.text('Log out'));
    await waitFor(tester, find.widgetWithText(FilledButton, 'Sign in'));
  });
}

/// The newest 6-digit code mailpit received after [after] (http://localhost:8025, the iOS simulator's host).
Future<String> mailpitCode({required DateTime after}) async {
  final client = HttpClient();
  try {
    for (var i = 0; i < 30; i++) {
      final request = await client.getUrl(Uri.parse('http://localhost:8025/api/v1/messages?limit=1'));
      final list = jsonDecode(await (await request.close()).transform(utf8.decoder).join()) as Map;
      final messages = list['messages'] as List;
      if (messages.isNotEmpty && DateTime.parse(messages.first['Created'] as String).isAfter(after)) {
        final id = messages.first['ID'];
        final body = jsonDecode(await (await (await client.getUrl(Uri.parse('http://localhost:8025/api/v1/message/$id'))).close()).transform(utf8.decoder).join()) as Map;
        final code = RegExp(r'\b\d{6}\b').firstMatch(body['Text'] as String);
        if (code != null) return code.group(0)!;
      }
      await Future<void>.delayed(const Duration(seconds: 1));
    }
    throw TestFailure('No code arrived in mailpit');
  } finally {
    client.close();
  }
}
