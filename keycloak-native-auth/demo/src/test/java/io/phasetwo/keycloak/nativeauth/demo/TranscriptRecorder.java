package io.phasetwo.keycloak.nativeauth.demo;

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.core.util.Separators;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.restassured.RestAssured;
import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.http.Header;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Records every request/response pair the integration tests exchange with the native-auth and
 * OIDC token endpoints as one JSON transcript per test method under {@code target/transcripts/}
 * (system property {@code transcripts.dir}). The committed, curated copy in {@code
 * demo/transcripts/} is the iOS SDK's contract fixture set (spec/05 §7, spec/10 Phase 1b);
 * {@code scripts/update-transcripts.sh} refreshes it.
 *
 * <p>Format (one file, {@code <TestClass>.<method>.json}):
 *
 * <pre>
 * { "test", "recorded_at", "keycloak_image", "base_url", "masked_form_fields": [...],
 *   "exchanges": [ { "seq", "request": { "method", "path", "headers", "form" | "json" | "body" },
 *                    "response": { "status", "headers", "json" | "body" } } ] }
 * </pre>
 *
 * <p>Masking: the form fields in {@link #MASKED_FORM_FIELDS} and the {@code Authorization} /
 * {@code DPoP} request headers are replaced by {@code ***}. Response bodies and JSON request bodies
 * are recorded verbatim (the realm keys and sessions behind the recorded {@code auth_session} and
 * token values die with the test container, so they are not usable secrets). Only requests to
 * {@code /realms/<realm>/native-auth/**} and {@code /realms/<realm>/protocol/openid-connect/**}
 * are recorded; admin API calls are not part of the contract.
 */
public final class TranscriptRecorder implements Filter, BeforeEachCallback, AfterEachCallback {

  public static final String MASK = "***";

  /** Form fields whose values are never written to a transcript. */
  public static final Set<String> MASKED_FORM_FIELDS =
      Set.of("password", "password_confirm", "totp", "otp", "recovery_code", "code_verifier", "client_secret", "refresh_token", "token");

  /**
   * Masked only on the challenge endpoint: there {@code code} is the e-mail verification code
   * (spec/03 §4.13); on the token endpoint it is the authorization code, recorded verbatim so the
   * SDK replay can check that the right code is exchanged.
   */
  public static final Set<String> MASKED_CHALLENGE_FORM_FIELDS = Set.of("code");

  /**
   * JSON request fields replaced by {@code ***}: the device-signed JWTs of the push device API
   * (spec/03 §7) carry the APNs device token and are signed by a per-run key the SDK cannot
   * reproduce; the replay only checks that the field is present.
   */
  public static final Set<String> MASKED_JSON_FIELDS = Set.of("token");

  private static final Set<String> MASKED_HEADERS = Set.of("authorization", "dpop");
  private static final Set<String> REQUEST_HEADERS = Set.of("accept", "content-type", "authorization", "dpop");
  private static final Set<String> RESPONSE_HEADERS = Set.of("content-type", "cache-control", "pragma", "www-authenticate");

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final ObjectWriter WRITER;

  static {
    DefaultIndenter indenter = new DefaultIndenter("  ", "\n");
    DefaultPrettyPrinter printer =
        new DefaultPrettyPrinter()
            .withSeparators(Separators.createDefaultInstance().withObjectFieldValueSpacing(Separators.Spacing.AFTER))
            .withObjectIndenter(indenter)
            .withArrayIndenter(indenter);
    WRITER = MAPPER.writer(printer);
  }

  private static final AtomicReference<Scenario> CURRENT = new AtomicReference<>();
  private static volatile boolean installed;

  /** The exchanges of one test method (or of a named setup block). */
  private static final class Scenario {
    final String name;
    final List<Map<String, Object>> exchanges = new ArrayList<>();

    Scenario(String name) {
      this.name = name;
    }
  }

  /** Registers the filter with RestAssured once; safe to call repeatedly. */
  static synchronized void install() {
    if (!installed) {
      RestAssured.filters(new TranscriptRecorder());
      installed = true;
    }
  }

  /** Records the exchanges made by {@code body} under {@code name} (for {@code @BeforeAll} setup). */
  static void scenario(String name, Runnable body) {
    Scenario previous = CURRENT.getAndSet(new Scenario(name));
    try {
      body.run();
    } finally {
      Scenario done = CURRENT.getAndSet(previous);
      write(done);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // JUnit extension: one scenario per test method

  @Override
  public void beforeEach(ExtensionContext context) {
    install();
    CURRENT.set(new Scenario(context.getRequiredTestClass().getSimpleName() + "." + context.getRequiredTestMethod().getName()));
  }

  @Override
  public void afterEach(ExtensionContext context) {
    write(CURRENT.getAndSet(null));
  }

  // ---------------------------------------------------------------------------------------------
  // RestAssured filter

  @Override
  public Response filter(FilterableRequestSpecification requestSpec, FilterableResponseSpecification responseSpec, FilterContext ctx) {
    Response response = ctx.next(requestSpec, responseSpec);
    Scenario scenario = CURRENT.get();
    String path = URI.create(requestSpec.getURI()).getRawPath();
    if (scenario != null && isRecordable(path)) {
      Map<String, Object> exchange = new LinkedHashMap<>();
      exchange.put("seq", scenario.exchanges.size() + 1);
      exchange.put("request", request(requestSpec, path));
      exchange.put("response", response(response));
      scenario.exchanges.add(exchange);
    }
    return response;
  }

  private static boolean isRecordable(String path) {
    String prefix = "/realms/" + KeycloakContainerSupport.REALM + "/";
    return path.startsWith(prefix + "native-auth/") || path.startsWith(prefix + "protocol/openid-connect/") || path.startsWith(prefix + "push-mfa/");
  }

  private static Map<String, Object> request(FilterableRequestSpecification spec, String path) {
    Map<String, Object> req = new LinkedHashMap<>();
    req.put("method", spec.getMethod());
    req.put("path", path);
    Map<String, String> headers = new LinkedHashMap<>();
    if (spec.getContentType() != null) headers.put("Content-Type", spec.getContentType());
    for (Header h : spec.getHeaders()) {
      String name = h.getName().toLowerCase(Locale.ROOT);
      if (!REQUEST_HEADERS.contains(name)) continue;
      headers.put(h.getName(), MASKED_HEADERS.contains(name) ? maskHeader(h.getValue()) : h.getValue());
    }
    if (!headers.isEmpty()) req.put("headers", headers);
    Map<String, ?> form = spec.getFormParams();
    if (form != null && !form.isEmpty()) {
      Map<String, String> masked = new LinkedHashMap<>();
      boolean challengeEndpoint = path.endsWith("/native-auth/challenge");
      // RestAssured keeps a NoParameterValue marker for a form param sent without a value.
      form.forEach((k, v) -> masked.put(k, MASKED_FORM_FIELDS.contains(k) || (challengeEndpoint && MASKED_CHALLENGE_FORM_FIELDS.contains(k)) ? MASK : (v instanceof String s ? s : "")));
      req.put("form", masked);
    }
    Object body = spec.getBody();
    if (body != null) {
      String text = body instanceof byte[] bytes ? new String(bytes, java.nio.charset.StandardCharsets.UTF_8) : String.valueOf(body);
      putBody(req, spec.getContentType(), text);
      if (req.get("json") instanceof com.fasterxml.jackson.databind.node.ObjectNode object) {
        for (String field : MASKED_JSON_FIELDS) {
          if (object.has(field)) object.put(field, MASK);
        }
      }
    }
    return req;
  }

  private static Map<String, Object> response(Response response) {
    Map<String, Object> res = new LinkedHashMap<>();
    res.put("status", response.getStatusCode());
    Map<String, String> headers = new LinkedHashMap<>();
    for (Header h : response.getHeaders()) {
      if (RESPONSE_HEADERS.contains(h.getName().toLowerCase(Locale.ROOT))) headers.put(h.getName(), h.getValue());
    }
    if (!headers.isEmpty()) res.put("headers", headers);
    putBody(res, response.getContentType(), response.getBody().asString());
    return res;
  }

  private static void putBody(Map<String, Object> target, String contentType, String text) {
    if (text == null || text.isEmpty()) return;
    if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json")) {
      try {
        JsonNode node = MAPPER.readTree(text);
        target.put("json", node);
        return;
      } catch (IOException ignored) {
        // not JSON after all: fall through
      }
    }
    if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("html")) {
      // Browser pages (the authorization endpoint during redirect_to_web) are not part of the contract.
      target.put("body_omitted", contentType + ", " + text.length() + " chars");
      return;
    }
    target.put("body", text);
  }

  private static String maskHeader(String value) {
    int space = value.indexOf(' ');
    return space > 0 ? value.substring(0, space) + " " + MASK : MASK;
  }

  // ---------------------------------------------------------------------------------------------

  private static void write(Scenario scenario) {
    if (scenario == null || scenario.exchanges.isEmpty()) return;
    File dir = new File(System.getProperty("transcripts.dir", "target/transcripts"));
    if (!dir.isDirectory() && !dir.mkdirs()) {
      throw new IllegalStateException("cannot create " + dir.getAbsolutePath());
    }
    Map<String, Object> doc = new LinkedHashMap<>();
    doc.put("test", scenario.name);
    doc.put("recorded_at", Instant.now().toString());
    doc.put("keycloak_image", System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.8.1"));
    doc.put("base_url", KeycloakContainerSupport.baseUrl());
    doc.put("masked_form_fields", new TreeSet<>(MASKED_FORM_FIELDS));
    doc.put("exchanges", scenario.exchanges);
    try {
      WRITER.writeValue(new File(dir, scenario.name + ".json"), doc);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
