// The Android SDK (spec/17). `core` is plain Kotlin/JVM: the challenge state machine and everything
// that does not need Android, tested on any JDK against the server's recorded transcripts
// (../keycloak-native-auth/demo/transcripts). `android` holds the platform pieces (Credential Manager,
// Keystore, Auth Tab) and needs the Android SDK; `ui` the Compose screens, `push` the FCM side of push MFA;
// the demo app follows (spec/17 §6 step C).
pluginManagement {
  repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
  }
}

rootProject.name = "keycloak-native-android"

dependencyResolutionManagement {
  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
  repositories {
    google()
    mavenCentral()
  }
}

include(":core")
include(":android")
include(":ui")
include(":push")
