plugins {
  alias(libs.plugins.android.library)
}

base {
  archivesName = "keycloak-native-push"
}

android {
  namespace = "io.phasetwo.keycloak.nativeauth.sdk.push.fcm"
  compileSdk = 37

  defaultConfig {
    minSdk = 28
    consumerProguardFiles("consumer-rules.pro")
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }

  testOptions {
    unitTests.isReturnDefaultValues = true
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
  // The protocol side of push MFA (enrollment, approvals, maintenance) is `Push` in core; this module
  // adds Firebase Cloud Messaging. The app applies the google-services plugin with its own project.
  api(project(":core"))
  api(platform(libs.firebase.bom))
  api(libs.firebase.messaging)
  implementation(libs.coroutines.play.services)

  testImplementation(libs.junit4)
  testImplementation(libs.coroutines.test)
}
