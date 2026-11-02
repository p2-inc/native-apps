plugins {
  alias(libs.plugins.kotlin.jvm) apply false
  alias(libs.plugins.kotlin.serialization) apply false
}

// One version line with the server and the iOS SDK (README "Releases").
allprojects {
  group = "io.phasetwo.keycloak.nativeauth"
  version = "0.1.0-SNAPSHOT"
}
