import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'keycloak_native_method_channel.dart';

abstract class KeycloakNativePlatform extends PlatformInterface {
  /// Constructs a KeycloakNativePlatform.
  KeycloakNativePlatform() : super(token: _token);

  static final Object _token = Object();

  static KeycloakNativePlatform _instance = MethodChannelKeycloakNative();

  /// The default instance of [KeycloakNativePlatform] to use.
  ///
  /// Defaults to [MethodChannelKeycloakNative].
  static KeycloakNativePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [KeycloakNativePlatform] when
  /// they register themselves.
  static set instance(KeycloakNativePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
