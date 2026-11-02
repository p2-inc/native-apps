plugins {
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.kotlin.serialization)
}

base {
  archivesName = "keycloak-native-core"
}

kotlin {
  // Java 17 bytecode: what Android's toolchain desugars; the build itself runs on JDK 21.
  jvmToolchain(21)
  compilerOptions {
    jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    allWarningsAsErrors = true
  }
  explicitApi()
}

tasks.withType<JavaCompile>().configureEach {
  options.release = 17
}

dependencies {
  api(libs.coroutines.core)
  implementation(libs.serialization.json)

  testImplementation(platform(libs.junit.bom))
  testImplementation(libs.junit.jupiter)
  testImplementation(libs.coroutines.test)
  testRuntimeOnly(libs.junit.launcher)
}

tasks.test {
  useJUnitPlatform()
  // The contract fixtures are read in place, not copied (spec/17 §5); KEYCLOAK_NATIVE_TRANSCRIPTS overrides.
  val transcripts = rootDir.resolve("../keycloak-native-auth/demo/transcripts").canonicalFile
  inputs.dir(transcripts).withPathSensitivity(PathSensitivity.RELATIVE)
  systemProperty("keycloak.native.transcripts", transcripts.absolutePath)
}
