package io.phasetwo.keycloak.nativeauth.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A fake Firebase Cloud Messaging for ba-itsys' {@code fcm} sender (spec/17 §6 A3). It stands in
 * for both Google endpoints the sender calls:
 *
 * <ul>
 *   <li>{@code POST /token}, the service account's {@code token_uri}: the JWT-bearer grant whose
 *       {@code assertion} is signed with the service account's RSA key; answers an access token.
 *   <li>{@code POST /v1/projects/{project}/messages:send}, the HTTP v1 send endpoint configured as
 *       {@code googleFcmUrl}: records the bearer token and the JSON message; answers like Google.
 * </ul>
 *
 * The RSA key pair is generated here and written into a service-account file in Google's format,
 * which Keycloak reads from {@code GOOGLE_APPLICATION_CREDENTIALS}.
 */
final class FcmSink {

  static final String PROJECT_ID = "demo-project";
  static final String CLIENT_EMAIL = "push-sender@demo-project.iam.gserviceaccount.com";
  static final String ACCESS_TOKEN = "fake-fcm-access-token";
  /** Where the service-account file is copied in the Keycloak container. */
  static final String CREDENTIALS_PATH = "/opt/keycloak/conf/fcm-service-account.json";

  record TokenRequest(Map<String, String> form) {
    String assertion() {
      return form.get("assertion");
    }
  }

  record Delivery(String authorization, JsonNode body) {
    JsonNode message() {
      return body.path("message");
    }

    String registrationToken() {
      return message().path("token").asText(null);
    }

    String confirmToken() {
      return message().path("data").path("token").asText(null);
    }
  }

  private final HttpServer server;
  private final KeyPair serviceAccountKey;
  private final List<TokenRequest> tokenRequests = new ArrayList<>();
  private final List<Delivery> deliveries = new ArrayList<>();

  private FcmSink(HttpServer server, KeyPair serviceAccountKey) {
    this.server = server;
    this.serviceAccountKey = serviceAccountKey;
  }

  static FcmSink start() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
      FcmSink sink = new FcmSink(server, kpg.generateKeyPair());
      server.createContext("/token", exchange -> {
        String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        synchronized (sink.tokenRequests) {
          sink.tokenRequests.add(new TokenRequest(form(raw)));
        }
        respond(exchange, 200, json(Map.of("access_token", ACCESS_TOKEN, "expires_in", 3599, "token_type", "Bearer")));
      });
      server.createContext("/v1/projects/", exchange -> {
        JsonNode body = new ObjectMapper().readTree(exchange.getRequestBody().readAllBytes());
        synchronized (sink.deliveries) {
          sink.deliveries.add(new Delivery(exchange.getRequestHeaders().getFirst("Authorization"), body));
        }
        respond(exchange, 200, json(Map.of("name", "projects/" + PROJECT_ID + "/messages/" + System.nanoTime())));
      });
      server.start();
      Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
      return sink;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }

  private static Map<String, String> form(String raw) {
    Map<String, String> form = new LinkedHashMap<>();
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      if (eq > 0) form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8), URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return form;
  }

  int port() {
    return server.getAddress().getPort();
  }

  /** The service account's token endpoint as the container reaches it. */
  String tokenUri() {
    return "http://host.testcontainers.internal:" + port() + "/token";
  }

  /** The HTTP v1 send URL as the container reaches it (the sender's {@code googleFcmUrl}). */
  String sendUrl() {
    return "http://host.testcontainers.internal:" + port() + "/v1/projects/" + PROJECT_ID + "/messages:send";
  }

  PublicKey serviceAccountPublicKey() {
    return serviceAccountKey.getPublic();
  }

  /** A service-account key file in Google's JSON format, with {@code token_uri} pointing here. */
  File serviceAccountFile() {
    Map<String, Object> account = new LinkedHashMap<>();
    account.put("type", "service_account");
    account.put("project_id", PROJECT_ID);
    account.put("private_key_id", "test-key-1");
    account.put("private_key", "-----BEGIN PRIVATE KEY-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(serviceAccountKey.getPrivate().getEncoded())
        + "\n-----END PRIVATE KEY-----\n");
    account.put("client_email", CLIENT_EMAIL);
    account.put("client_id", "100000000000000000001");
    account.put("token_uri", tokenUri());
    try {
      File file = File.createTempFile("fcm-service-account-", ".json");
      file.deleteOnExit();
      new ObjectMapper().writeValue(file, account);
      return file;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  List<TokenRequest> tokenRequests() {
    synchronized (tokenRequests) {
      return List.copyOf(tokenRequests);
    }
  }

  List<Delivery> deliveries() {
    synchronized (deliveries) {
      return List.copyOf(deliveries);
    }
  }

  void clear() {
    synchronized (deliveries) {
      deliveries.clear();
    }
    synchronized (tokenRequests) {
      tokenRequests.clear();
    }
  }

  /** The newest message to {@code registrationToken}, waiting briefly for it. */
  Delivery latest(String registrationToken) {
    long deadline = System.currentTimeMillis() + 5_000;
    while (System.currentTimeMillis() < deadline) {
      List<Delivery> all = deliveries();
      for (int i = all.size() - 1; i >= 0; i--) {
        if (registrationToken.equals(all.get(i).registrationToken())) return all.get(i);
      }
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    throw new AssertionError("no FCM message to " + registrationToken + " in " + deliveries() + "; token requests " + tokenRequests());
  }

  static String json(Object value) {
    try {
      return new ObjectMapper().writeValueAsString(value);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
