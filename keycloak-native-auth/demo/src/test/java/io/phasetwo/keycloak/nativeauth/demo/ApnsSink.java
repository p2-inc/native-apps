package io.phasetwo.keycloak.nativeauth.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * A fake APNs (spec/14 D10): accepts {@code POST /3/device/{token}}, records the headers and JSON
 * body the {@code apns} sender sends, and answers {@code 200} with an {@code apns-id} like Apple.
 * The provider token is not verified (Apple would); its key pair is generated here and handed to
 * Keycloak as the {@code .p8} key so the sender has something to sign with.
 */
final class ApnsSink {

  static final String TEAM_ID = "TESTTEAM12";
  static final String KEY_ID = "TESTKEY123";
  static final String TOPIC = "io.phasetwo.keycloak.nativedemo";

  record Delivery(String deviceToken, String topic, String collapseId, String pushType, String authorization, JsonNode body) {
    String confirmToken() {
      return body.path("confirmToken").asText(null);
    }

    String cid() {
      return body.path("cid").asText(null);
    }
  }

  private final HttpServer server;
  private final KeyPair providerKey;
  private final List<Delivery> deliveries = new ArrayList<>();

  private ApnsSink(HttpServer server, KeyPair providerKey) {
    this.server = server;
    this.providerKey = providerKey;
  }

  static ApnsSink start() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair keyPair = kpg.generateKeyPair();
      HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
      ApnsSink sink = new ApnsSink(server, keyPair);
      server.createContext("/3/device/", exchange -> {
        String path = exchange.getRequestURI().getPath();
        String token = path.substring(path.lastIndexOf('/') + 1);
        byte[] raw = exchange.getRequestBody().readAllBytes();
        JsonNode body = new ObjectMapper().readTree(raw);
        synchronized (sink.deliveries) {
          sink.deliveries.add(
              new Delivery(
                  token,
                  exchange.getRequestHeaders().getFirst("apns-topic"),
                  exchange.getRequestHeaders().getFirst("apns-collapse-id"),
                  exchange.getRequestHeaders().getFirst("apns-push-type"),
                  exchange.getRequestHeaders().getFirst("Authorization"),
                  body));
        }
        exchange.getResponseHeaders().add("apns-id", UUID.randomUUID().toString());
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
      });
      server.start();
      Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
      return sink;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  int port() {
    return server.getAddress().getPort();
  }

  /** PKCS#8 PEM of the test provider key, what Apple's {@code .p8} file contains. */
  String providerKeyPem() {
    return "-----BEGIN PRIVATE KEY-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(providerKey.getPrivate().getEncoded())
        + "\n-----END PRIVATE KEY-----\n";
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
  }

  /** The newest delivery to {@code deviceToken}, waiting briefly for it. */
  Delivery latest(String deviceToken) {
    long deadline = System.currentTimeMillis() + 5_000;
    while (System.currentTimeMillis() < deadline) {
      List<Delivery> all = deliveries();
      for (int i = all.size() - 1; i >= 0; i--) {
        if (deviceToken.equals(all.get(i).deviceToken())) return all.get(i);
      }
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    throw new AssertionError("no APNs delivery to " + deviceToken + " in " + deliveries());
  }

  static String json(Object value) {
    try {
      return new ObjectMapper().writeValueAsString(value);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
