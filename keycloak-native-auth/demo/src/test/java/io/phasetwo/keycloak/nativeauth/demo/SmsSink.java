package io.phasetwo.keycloak.nativeauth.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An in-JVM webhook standing in for an SMS gateway: records every {@code {"to","message"}} the
 * {@code sms-webhook} sender posts (spec/03 §4.6, spec/13 D4) and checks the bearer token.
 */
final class SmsSink {

  static final String TOKEN = "sms-sink-token";
  private static final Pattern CODE = Pattern.compile("code is (\\d{4,10})");

  record Message(String to, String message, String authorization) {}

  private final HttpServer server;
  private final List<Message> messages = new ArrayList<>();

  private SmsSink(HttpServer server) {
    this.server = server;
  }

  static SmsSink start() {
    try {
      HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
      SmsSink sink = new SmsSink(server);
      server.createContext("/sms", exchange -> {
        byte[] body = exchange.getRequestBody().readAllBytes();
        JsonNode json = new ObjectMapper().readTree(body);
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        synchronized (sink.messages) {
          sink.messages.add(new Message(json.path("to").asText(null), json.path("message").asText(null), authorization));
        }
        byte[] response = "{\"status\":\"queued\"}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(TOKEN.equals(stripBearer(authorization)) ? 202 : 401, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
      });
      server.start();
      Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
      return sink;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static String stripBearer(String authorization) {
    return authorization != null && authorization.startsWith("Bearer ") ? authorization.substring(7) : null;
  }

  int port() {
    return server.getAddress().getPort();
  }

  List<Message> messages() {
    synchronized (messages) {
      return List.copyOf(messages);
    }
  }

  void clear() {
    synchronized (messages) {
      messages.clear();
    }
  }

  /** The code in the newest message to {@code number}. */
  String latestCode(String number) {
    List<Message> all = messages();
    for (int i = all.size() - 1; i >= 0; i--) {
      if (number.equals(all.get(i).to())) {
        Matcher m = CODE.matcher(all.get(i).message());
        if (m.find()) return m.group(1);
        throw new AssertionError("no code in SMS: " + all.get(i).message());
      }
    }
    throw new AssertionError("no SMS to " + number + " in " + all);
  }
}
