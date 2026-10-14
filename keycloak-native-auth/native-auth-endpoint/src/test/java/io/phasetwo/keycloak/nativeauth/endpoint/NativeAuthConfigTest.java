package io.phasetwo.keycloak.nativeauth.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class NativeAuthConfigTest {

  @Test
  void parsesModes() {
    assertEquals(NativeAuthConfig.CodeRedirectUriMode.NONE, NativeAuthConfig.CodeRedirectUriMode.parse(null));
    assertEquals(NativeAuthConfig.CodeRedirectUriMode.NONE, NativeAuthConfig.CodeRedirectUriMode.parse(""));
    assertEquals(NativeAuthConfig.CodeRedirectUriMode.NONE, NativeAuthConfig.CodeRedirectUriMode.parse("none"));
    assertEquals(NativeAuthConfig.CodeRedirectUriMode.SENTINEL, NativeAuthConfig.CodeRedirectUriMode.parse("Sentinel"));
    assertEquals(NativeAuthConfig.CodeRedirectUriMode.CLIENT_FIXED, NativeAuthConfig.CodeRedirectUriMode.parse("client-fixed"));
    assertEquals(NativeAuthConfig.CodeRedirectUriMode.CLIENT_FIXED, NativeAuthConfig.CodeRedirectUriMode.parse("client_fixed"));
    assertThrows(IllegalArgumentException.class, () -> NativeAuthConfig.CodeRedirectUriMode.parse("bogus"));
  }
}
