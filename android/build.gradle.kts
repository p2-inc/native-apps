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
  version = providers.gradleProperty("releaseVersion").getOrElse("0.3.0-SNAPSHOT")
}

// Apps compile against the libraries with their own Kotlin compiler, which reads class metadata up to
// one version newer than itself. The libraries are written at language and API level 2.2 and depend on
// a 2.2 standard library, so apps on Kotlin 2.2 or later (React Native 0.88's default) can use them
// while the build runs Kotlin 2.4 (docs/android-integration.md "Kotlin version"). The demo app is not
// consumed by anything and keeps the compiler's own level.
subprojects {
  if (name == "demo") return@subprojects
  tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask<*>>().configureEach {
    compilerOptions {
      languageVersion = org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2
      apiVersion = org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2
    }
  }
  // Apps compile against the libraries with compileSdk 36 or later: AGP 9 would otherwise record the
  // libraries' own compileSdk (37) as the minimum, while their dependencies need 36 and the code
  // calls nothing newer at runtime than minSdk allows.
  plugins.withId("com.android.library") {
    extensions.configure<com.android.build.api.dsl.LibraryExtension> {
      defaultConfig { aarMetadata { minCompileSdk = 36 } }
    }
  }
  // After the module's plugins: the Android plugin registers the kotlin extension late.
  afterEvaluate {
    extensions.findByType<org.jetbrains.kotlin.gradle.dsl.KotlinProjectExtension>()?.coreLibrariesVersion = "2.2.20"
  }
}

// The libraries publish to a Maven repository under build/maven-repo, which the release workflow
// zips, attaches to the GitHub release and uploads to Maven Central (README "Releases"). Central
// requires signatures: with SIGNING_KEY (an ASCII-armored private key) set, every publication is signed.
subprojects {
  plugins.withId("maven-publish") {
    val signingKey = providers.environmentVariable("SIGNING_KEY")
    if (signingKey.isPresent) {
      apply(plugin = "signing")
      extensions.configure<SigningExtension> {
        useInMemoryPgpKeys(signingKey.get(), providers.environmentVariable("SIGNING_PASSWORD").getOrElse(""))
        sign(extensions.getByType<PublishingExtension>().publications)
      }
    }
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
          developers {
            developer {
              name = "Phase Two"
              email = "support@phasetwo.io"
              organization = "Phase Two, Inc."
              organizationUrl = "https://phasetwo.io"
            }
          }
          organization {
            name = "Phase Two, Inc."
            url = "https://phasetwo.io"
          }
          scm {
            url = "https://github.com/p2-inc/native-apps"
            connection = "scm:git:https://github.com/p2-inc/native-apps.git"
            developerConnection = "scm:git:git@github.com:p2-inc/native-apps.git"
          }
        }
      }
    }
  }
}
