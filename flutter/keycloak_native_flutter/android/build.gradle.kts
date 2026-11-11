// The Android half of the Flutter plugin (spec/18 §3): a bridge from the Pigeon host API to the
// Android SDK (io.phasetwo.keycloak.nativeauth:keycloak-native-android). Inside this repository the
// example app substitutes the SDK from ../../../android with a Gradle composite build
// (example/android/settings.gradle.kts), so nothing waits on a published artifact; apps that use the
// plugin from pub.dev resolve it from Maven Central.
group = "io.phasetwo.keycloak.nativeauth.flutter"
version = "0.4.0-SNAPSHOT"

buildscript {
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        // The versions of the Android SDK's build (android/gradle/libs.versions.toml): one build may
        // load each Gradle plugin in one version only, and the composite build loads both.
        classpath("com.android.tools.build:gradle:9.5.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

plugins {
    id("com.android.library")
}

/** The SDK version this plugin release is built against; the plugin and the SDKs share one version line. */
val keycloakNativeVersion = "0.4.0-SNAPSHOT"

android {
    namespace = "io.phasetwo.keycloak.nativeauth.flutter"

    // The Android SDK compiles against 37 and its AARs require at least that.
    compileSdk = 37

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
    }

    defaultConfig {
        // Credential Manager passkeys and Keystore StrongBox start at API 28, like the Android SDK.
        minSdk = 28
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    implementation("io.phasetwo.keycloak.nativeauth:keycloak-native-android:$keycloakNativeVersion")
    // AuthTabWebPresenter takes a ComponentActivity (FlutterFragmentActivity).
    implementation("androidx.activity:activity:1.13.0")
    // Pigeon's suspend host methods run on Dispatchers.Main.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}
