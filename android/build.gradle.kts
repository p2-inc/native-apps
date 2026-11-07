plugins {
  alias(libs.plugins.android.library) apply false
  alias(libs.plugins.android.application) apply false
  alias(libs.plugins.google.services) apply false
  alias(libs.plugins.kotlin.jvm) apply false
  alias(libs.plugins.kotlin.serialization) apply false
  alias(libs.plugins.kotlin.compose) apply false
}

// One version line with the server and the iOS SDK (README "Releases").
allprojects {
  group = "io.phasetwo.keycloak.nativeauth"
  // The release workflow passes the tag (.github/workflows/release.yml).
  version = providers.gradleProperty("releaseVersion").getOrElse("0.1.0-SNAPSHOT")
}

// The libraries publish to a Maven repository under build/maven-repo, which the release workflow
// zips and attaches to the GitHub release (README "Releases").
subprojects {
  plugins.withId("maven-publish") {
    extensions.configure<PublishingExtension> {
      repositories {
        maven {
          name = "release"
          url = uri(rootProject.layout.buildDirectory.dir("maven-repo"))
        }
      }
      publications.withType<MavenPublication>().configureEach {
        pom {
          name = "Keycloak Native ${project.name}"
          description = "Native authentication for Keycloak: the Android SDK's ${project.name} module."
          url = "https://github.com/p2-inc/native-apps"
          licenses {
            license {
              name = "Apache License, Version 2.0"
              url = "https://www.apache.org/licenses/LICENSE-2.0"
            }
          }
          organization {
            name = "Phase Two, Inc."
            url = "https://phasetwo.io"
          }
          scm {
            url = "https://github.com/p2-inc/native-apps"
          }
        }
      }
    }
  }
}
