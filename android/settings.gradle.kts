// The Android SDK (spec/17). `core` is plain Kotlin/JVM: the challenge state machine and everything
// that does not need Android, tested on any JDK against the server's recorded transcripts
// (../keycloak-native-auth/demo/transcripts). The Android library modules (android, push, ui) and the
// demo app join this build in spec/17 §6 step C.
rootProject.name = "keycloak-native-android"

dependencyResolutionManagement {
  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
  repositories {
    mavenCentral()
  }
}

include(":core")
