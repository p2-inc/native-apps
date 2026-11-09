
import 'keycloak_native_platform_interface.dart';

class KeycloakNative {
  Future<String?> getPlatformVersion() {
    return KeycloakNativePlatform.instance.getPlatformVersion();
  }
}
