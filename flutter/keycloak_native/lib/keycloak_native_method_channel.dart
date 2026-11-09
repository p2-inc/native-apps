import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'keycloak_native_platform_interface.dart';

/// An implementation of [KeycloakNativePlatform] that uses method channels.
class MethodChannelKeycloakNative extends KeycloakNativePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('keycloak_native');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>(
      'getPlatformVersion',
    );
    return version;
  }
}
