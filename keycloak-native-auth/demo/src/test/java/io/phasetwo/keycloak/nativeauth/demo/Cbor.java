package io.phasetwo.keycloak.nativeauth.demo;

import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * Minimal CBOR encoder (RFC 8949) for the two structures a WebAuthn authenticator emits: the
 * attestation object and a COSE key. Supports integers (keys and values), text strings, byte strings
 * and maps; nothing else is needed by the tests.
 */
final class Cbor {

  private Cbor() {}

  static byte[] encode(Object value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write(out, value);
    return out.toByteArray();
  }

  private static void write(ByteArrayOutputStream out, Object value) {
    if (value instanceof Integer i) {
      writeInt(out, i.longValue());
    } else if (value instanceof Long l) {
      writeInt(out, l);
    } else if (value instanceof String s) {
      byte[] utf8 = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      writeHeader(out, 3, utf8.length);
      out.writeBytes(utf8);
    } else if (value instanceof byte[] b) {
      writeHeader(out, 2, b.length);
      out.writeBytes(b);
    } else if (value instanceof Map<?, ?> m) {
      writeHeader(out, 5, m.size());
      for (Map.Entry<?, ?> e : m.entrySet()) {
        write(out, e.getKey());
        write(out, e.getValue());
      }
    } else {
      throw new IllegalArgumentException("unsupported CBOR value: " + value);
    }
  }

  private static void writeInt(ByteArrayOutputStream out, long v) {
    if (v >= 0) writeHeader(out, 0, v);
    else writeHeader(out, 1, -1 - v);
  }

  private static void writeHeader(ByteArrayOutputStream out, int major, long n) {
    int mt = major << 5;
    if (n < 24) {
      out.write(mt | (int) n);
    } else if (n < 0x100) {
      out.write(mt | 24);
      out.write((int) n);
    } else if (n < 0x10000) {
      out.write(mt | 25);
      out.write((int) (n >> 8));
      out.write((int) n);
    } else {
      out.write(mt | 26);
      out.write((int) (n >> 24));
      out.write((int) (n >> 16));
      out.write((int) (n >> 8));
      out.write((int) n);
    }
  }
}
