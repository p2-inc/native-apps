import 'package:flutter_test/flutter_test.dart';
import 'package:keycloak_native/keycloak_native.dart';
import 'package:keycloak_native/keycloak_native_platform_interface.dart';
import 'package:keycloak_native/keycloak_native_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockKeycloakNativePlatform
    with MockPlatformInterfaceMixin
    implements KeycloakNativePlatform {
  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final KeycloakNativePlatform initialPlatform = KeycloakNativePlatform.instance;

  test('$MethodChannelKeycloakNative is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelKeycloakNative>());
  });

  test('getPlatformVersion', () async {
    KeycloakNative keycloakNativePlugin = KeycloakNative();
    MockKeycloakNativePlatform fakePlatform = MockKeycloakNativePlatform();
    KeycloakNativePlatform.instance = fakePlatform;

    expect(await keycloakNativePlugin.getPlatformVersion(), '42');
  });
}
