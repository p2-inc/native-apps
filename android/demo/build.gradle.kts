plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.kotlin.compose)
}

// Firebase (push MFA over FCM) is optional: the google-services plugin needs the app's
// google-services.json, which stays outside the repository. Default location
// ~/.config/native-apps/google-services.json; override with -Pdemo.googleServicesJson=<path> or
// DEMO_GOOGLE_SERVICES_JSON. Without it the app builds and enrolls for push without delivery (`none`).
val googleServicesSource: File = file(
  providers.gradleProperty("demo.googleServicesJson")
    .orElse(providers.environmentVariable("DEMO_GOOGLE_SERVICES_JSON"))
    .getOrElse("${System.getProperty("user.home")}/.config/native-apps/google-services.json"),
)

// The plugin reads the file from the module directory only; the copy is git-ignored.
val googleServicesCopy: File = file("google-services.json")
val firebaseConfigured: Boolean = googleServicesSource.isFile
if (firebaseConfigured) {
  googleServicesSource.copyTo(googleServicesCopy, overwrite = true)
  apply(plugin = libs.plugins.google.services.get().pluginId)
} else {
  googleServicesCopy.delete()
}

/** Demo settings: -Pdemo.<name>=… or the defaults for the compose stack as the emulator sees it. */
fun demoSetting(name: String, default: String): String = providers.gradleProperty("demo.$name").getOrElse(default)

fun quoted(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
  namespace = "io.phasetwo.keycloak.nativedemo"
  compileSdk = 37

  defaultConfig {
    applicationId = "io.phasetwo.keycloak.nativedemo"
    minSdk = 28
    targetSdk = 37
    versionCode = 1
    versionName = "0.1.0"

    // 10.0.2.2 is the host's localhost from the emulator; compose publishes Keycloak on KC_PORT (8080).
    buildConfigField("String", "ISSUER", quoted(demoSetting("issuer", "http://10.0.2.2:8080/realms/demo")))
    buildConfigField("String", "CLIENT_ID", quoted(demoSetting("clientId", "demo-ios")))
    buildConfigField("String", "PASSKEY_CLIENT_ID", quoted(demoSetting("passkeyClientId", "demo-ios-passkey")))
    buildConfigField("String", "STEP_UP_CLIENT_ID", quoted(demoSetting("stepUpClientId", "demo-ios-stepup")))
    buildConfigField("String", "OTP_CLIENT_ID", quoted(demoSetting("otpClientId", "demo-ios-otp")))
    buildConfigField("String", "RESOURCE_SERVER", quoted(demoSetting("resourceServer", "http://10.0.2.2:8091")))
    buildConfigField("boolean", "ALLOW_RP_ID_MISMATCH", demoSetting("allowRpIdMismatch", "false"))
    buildConfigField("String", "DEVICE_NAME", quoted(demoSetting("deviceName", "KeycloakNativeDemo Android")))
    buildConfigField("boolean", "FIREBASE_CONFIGURED", firebaseConfigured.toString())
  }

  buildFeatures {
    compose = true
    buildConfig = true
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
}

dependencies {
  implementation(project(":android"))
  implementation(project(":ui"))
  implementation(project(":push"))
  implementation(platform(libs.compose.bom))
  implementation(libs.compose.ui)
  implementation(libs.compose.foundation)
  implementation(libs.compose.material3)
  implementation(libs.androidx.activity.compose)
  implementation(libs.coroutines.android)
}
