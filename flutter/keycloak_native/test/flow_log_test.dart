// The native flow log reaches the instance's `flowLog` stream (spec/18 §4).
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native/keycloak_native.dart';
import 'package:keycloak_native/src/messages.g.dart';

import 'support/transcript_host.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('entries the native side sends arrive on flowLog', () async {
    final host = TranscriptHostApi(loadTranscript('NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'));
    final kc = await KeycloakNative.configure(
      issuer: Uri.parse('http://localhost/realms/demo'),
      clientId: 'demo-native',
      options: const KeycloakNativeOptions(observeFlow: true),
      hostApi: host,
    );
    final received = <FlowLogEntry>[];
    final subscription = kc.flowLog.listen(received.add);
    final entry = FlowLogMessage(
      id: 'e1',
      timestampMillis: 0,
      method: 'POST',
      url: 'http://localhost/realms/demo/native-auth/challenge',
      requestHeaders: const {'DPoP': '***'},
      requestBody: 'username=alice&password=***',
      statusCode: 403,
      responseHeaders: const {},
      durationMilliseconds: 12,
    );
    const codec = KeycloakNativeFlutterApi.pigeonChannelCodec;
    await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.handlePlatformMessage(
      'dev.flutter.pigeon.keycloak_native.KeycloakNativeFlutterApi.onFlowLog',
      codec.encodeMessage(<Object?>[kc.handle, entry]),
      (_) {},
    );
    await Future<void>.delayed(Duration.zero);
    expect(received.single.statusCode, 403);
    expect(received.single.requestBody, contains('password=***'));
    expect(received.single.duration, const Duration(milliseconds: 12));
    await subscription.cancel();
  });
}
