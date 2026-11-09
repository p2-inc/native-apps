plugins {
  // AGP 9 compiles Kotlin itself (built-in Kotlin), with the Kotlin Gradle plugin the root build pins.
  alias(libs.plugins.android.library)
  `maven-publish`
}

base {
  archivesName = "keycloak-native-android"
}

android {
  namespace = "io.phasetwo.keycloak.nativeauth.sdk.android"
  compileSdk = 37

  publishing {
    singleVariant("release") {
      withSourcesJar()
      withJavadocJar()
    }
  }

  defaultConfig {
    // Credential Manager passkeys and Keystore StrongBox both start at API 28.
    minSdk = 28
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    consumerProguardFiles("consumer-rules.pro")
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }
}

kotlin {
  jvmToolchain(21)
  compilerOptions {
    jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    allWarningsAsErrors = true
  }
  explicitApi()
}

dependencies {
  api(project(":core"))
  // AuthTabWebPresenter takes a ComponentActivity.
  api(libs.androidx.activity)
  implementation(libs.androidx.lifecycle.common)
  implementation(libs.coroutines.android)
  implementation(libs.androidx.credentials)
  // Credential Manager's provider on Android 13 and lower (and the Google Password Manager on all versions).
  implementation(libs.androidx.credentials.play.services)
  implementation(libs.androidx.browser)

  androidTestImplementation(libs.androidx.test.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.coroutines.test)
}

publishing {
  publications {
    register<MavenPublication>("release") {
      artifactId = "keycloak-native-android"
      afterEvaluate { from(components["release"]) }
    }
  }
}
