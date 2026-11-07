plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.kotlin.compose)
  `maven-publish`
}

base {
  archivesName = "keycloak-native-ui"
}

android {
  namespace = "io.phasetwo.keycloak.nativeauth.sdk.ui"
  compileSdk = 37

  publishing {
    singleVariant("release") {
      withSourcesJar()
    }
  }

  defaultConfig {
    minSdk = 28
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    consumerProguardFiles("consumer-rules.pro")
  }

  buildFeatures {
    compose = true
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
  api(platform(libs.compose.bom))
  api(libs.compose.ui)
  api(libs.compose.material3)
  implementation(libs.compose.foundation)
  implementation(libs.compose.ui.tooling.preview)
  implementation(libs.coroutines.android)
  debugImplementation(libs.compose.ui.tooling)

  // The model is plain Kotlin over StateFlow: its tests run on the JVM.
  testImplementation(libs.junit4)
  testImplementation(libs.coroutines.test)

  androidTestImplementation(platform(libs.compose.bom))
  androidTestImplementation(libs.compose.ui.test.junit4)
  // The Compose test library's own Espresso (3.5) calls InputManager.getInstance, gone on API 36+.
  androidTestImplementation(libs.androidx.test.espresso)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.androidx.test.junit)
  androidTestImplementation(libs.coroutines.test)
  debugImplementation(libs.compose.ui.test.manifest)
}

publishing {
  publications {
    register<MavenPublication>("release") {
      artifactId = "keycloak-native-ui"
      afterEvaluate { from(components["release"]) }
    }
  }
}
