pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    // The Android SDK's versions (android/gradle/libs.versions.toml), which the composite build below
    // loads too: one build may load each Gradle plugin in one version only.
    id("com.android.application") version "9.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
}

include(":app")

// The plugin depends on io.phasetwo.keycloak.nativeauth:keycloak-native-android. Inside this
// repository it comes from the Android SDK's own build (spec/18 §8), so a change there is picked up
// here without publishing anything; apps outside the repository resolve the published artifact.
includeBuild("../../../../android") {
    dependencySubstitution {
        substitute(module("io.phasetwo.keycloak.nativeauth:keycloak-native-core")).using(project(":core"))
        substitute(module("io.phasetwo.keycloak.nativeauth:keycloak-native-android")).using(project(":android"))
    }
}
