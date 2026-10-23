package io.phasetwo.keycloak.nativeauth.core.compat;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;

/**
 * Shared ground for running one build of the extensions on every supported Keycloak version (26.4,
 * 26.6, 26.8; see the README's "Keycloak versions"). The extensions compile against the newest
 * version; a member an older version lacks is never called directly but resolved once through these
 * helpers by the module's own compat class ({@code ServicesCompat} in the endpoint, {@code
 * WebAuthnCompat} in the required actions). Add new version differences there, not at call sites.
 */
public final class KeycloakCompat {

  private KeycloakCompat() {}

  /** RFC 9126 §2.2; {@code ParEndpoint.REQUEST_URI_PREFIX} is private before 26.6. */
  public static final String PAR_REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

  /** {@code USER_ENTITY.USERNAME} is {@code varchar(255)} (Keycloak's {@code Validation.MAX_USERNAME_LENGTH}). */
  public static final int MAX_USERNAME_LENGTH = 255;

  /** {@code AuthenticatorUtils.isUsernameTooLong} (26.8+) for every version. */
  public static boolean isUsernameTooLong(String username) {
    return username != null && username.length() > MAX_USERNAME_LENGTH;
  }

  public static Optional<Class<?>> type(String name) {
    try {
      return Optional.of(Class.forName(name, false, KeycloakCompat.class.getClassLoader()));
    } catch (ClassNotFoundException | LinkageError e) {
      return Optional.empty();
    }
  }

  public static Optional<Method> method(Class<?> type, String name, Class<?>... parameters) {
    try {
      return Optional.of(type.getMethod(name, parameters));
    } catch (NoSuchMethodException e) {
      return Optional.empty();
    }
  }

  public static Optional<String> constant(Class<?> type, String name) {
    try {
      Field field = type.getField(name);
      return Optional.of((String) field.get(null));
    } catch (NoSuchFieldException | IllegalAccessException | ClassCastException e) {
      return Optional.empty();
    }
  }

  public static Optional<Constructor<?>> constructor(Class<?> type, int parameterCount) {
    return Arrays.stream(type.getConstructors()).filter(c -> c.getParameterCount() == parameterCount).findFirst();
  }

  public static Object invoke(Method method, Object target, Object... args) {
    try {
      return method.invoke(target, args);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw rethrow(e);
    }
  }

  public static Object create(Constructor<?> constructor, Object... args) {
    try {
      return constructor.newInstance(args);
    } catch (InstantiationException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw rethrow(e);
    }
  }

  private static RuntimeException rethrow(InvocationTargetException e) {
    Throwable cause = e.getCause();
    if (cause instanceof RuntimeException re) return re;
    if (cause instanceof Error err) throw err;
    return new IllegalStateException(cause);
  }
}
