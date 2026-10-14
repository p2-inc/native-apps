package io.phasetwo.keycloak.nativeauth.demo;

import static io.restassured.RestAssured.given;

import io.restassured.response.Response;
import java.io.File;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Starts {@code quay.io/keycloak/keycloak:<keycloak.image>} once per JVM with the provider JARs from
 * {@code demo/target/providers} and the demo realm import, and exposes small HTTP helpers.
 */
final class KeycloakContainerSupport {

  static final String REALM = "demo";
  static final String ADMIN = "admin";
  static final String ADMIN_PASSWORD = "admin";

  private static GenericContainer<?> container;
  private static String baseUrl;

  private KeycloakContainerSupport() {}

  static synchronized String baseUrl() {
    if (container == null) {
      String image = System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.8.1");
      File providers = new File(System.getProperty("providers.dir", "target/providers"));
      File realmExport = new File(System.getProperty("realm.export", "realm-export/demo-realm.json"));
      File[] jars = providers.listFiles((dir, name) -> name.endsWith(".jar"));
      if (jars == null || jars.length == 0) {
        throw new IllegalStateException(
            "No provider JARs in " + providers.getAbsolutePath() + "; run 'mvn package' first");
      }
      GenericContainer<?> kc =
          new GenericContainer<>(image)
              .withCommand("start-dev", "--import-realm")
              .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN)
              .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
              .withEnv("KC_HTTP_ENABLED", "true")
              .withEnv("KC_HOSTNAME_STRICT", "false")
              .withEnv("KC_LOG_LEVEL", "info,io.phasetwo.keycloak.nativeauth:debug")
              // Explicit 0644: docker cp keeps host modes, and a restrictive umask would make the files
              // unreadable for the container's keycloak user (uid 1000).
              .withCopyFileToContainer(
                  MountableFile.forHostPath(realmExport.getAbsolutePath(), 0644),
                  "/opt/keycloak/data/import/demo-realm.json")
              .withExposedPorts(8080)
              .waitingFor(
                  Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                      .forPort(8080)
                      .forStatusCode(200)
                      .withStartupTimeout(Duration.ofMinutes(5)));
      for (File jar : jars) {
        kc.withCopyFileToContainer(
            MountableFile.forHostPath(jar.getAbsolutePath(), 0644),
            "/opt/keycloak/providers/" + jar.getName());
      }
      StringBuilder startupLog = new StringBuilder();
      kc.withLogConsumer(frame -> startupLog.append(frame.getUtf8String()));
      try {
        kc.start();
      } catch (RuntimeException e) {
        System.err.println("---- Keycloak container log (last 8000 chars) ----");
        String log = startupLog.toString();
        System.err.println(log.substring(Math.max(0, log.length() - 8000)));
        throw e;
      }
      container = kc;
      baseUrl = "http://" + kc.getHost() + ":" + kc.getMappedPort(8080);
      Runtime.getRuntime().addShutdownHook(new Thread(kc::stop));
      TranscriptRecorder.install();
    }
    return baseUrl;
  }

  static String realmUrl() {
    return baseUrl() + "/realms/" + REALM;
  }

  static String logs() {
    return container == null ? "" : container.getLogs();
  }

  /** {@code POST /native-auth/challenge} with form parameters. */
  static Response challenge(Map<String, String> params) {
    return given()
        .accept("application/json")
        .contentType("application/x-www-form-urlencoded; charset=UTF-8")
        .formParams(params)
        .post(realmUrl() + "/native-auth/challenge")
        .andReturn();
  }

  static Map<String, String> params(String... kv) {
    Map<String, String> m = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) {
      m.put(kv[i], kv[i + 1]);
    }
    return m;
  }

  static String adminToken() {
    return given()
        .formParam("grant_type", "password")
        .formParam("client_id", "admin-cli")
        .formParam("username", ADMIN)
        .formParam("password", ADMIN_PASSWORD)
        .post(baseUrl() + "/realms/master/protocol/openid-connect/token")
        .then()
        .statusCode(200)
        .extract()
        .path("access_token");
  }

  static String adminRealmUrl() {
    return baseUrl() + "/admin/realms/" + REALM;
  }
}
