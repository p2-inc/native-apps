package io.phasetwo.keycloak.nativeauth.registration;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.theme.Theme;

/**
 * The login theme's messages (with the realm's overrides) in the request's locale, so field labels
 * ({@code ${firstName}}) and validation errors read as they do on Keycloak's pages.
 */
final class Messages {

  private static final Logger log = Logger.getLogger(Messages.class);
  private static final Pattern KEY = Pattern.compile("^\\$\\{(.+)}$");

  private final Properties messages;
  private final Locale locale;

  private Messages(Properties messages, Locale locale) {
    this.messages = messages;
    this.locale = locale;
  }

  static Messages of(KeycloakSession session, RealmModel realm) {
    Locale locale = session.getContext().resolveLocale(null);
    Properties messages = new Properties();
    try {
      Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
      messages = theme.getEnhancedMessages(realm, locale);
    } catch (Exception e) {
      log.debugf(e, "Login theme messages unavailable; labels stay as keys");
    }
    return new Messages(messages, locale);
  }

  /** {@code ${key}} → the message, a plain string as it is. */
  String label(String displayName, String fallback) {
    if (displayName == null || displayName.isBlank()) return fallback;
    Matcher m = KEY.matcher(displayName.trim());
    return m.matches() ? messages.getProperty(m.group(1), fallback) : displayName;
  }

  /** A message key with parameters, formatted; the key itself when the theme has none. */
  String format(String key, Object... parameters) {
    String pattern = messages.getProperty(key);
    if (pattern == null) return key;
    try {
      // Keycloak's messages are MessageFormat patterns already (quotes doubled).
      return new MessageFormat(pattern, locale).format(parameters == null ? new Object[0] : parameters);
    } catch (IllegalArgumentException e) {
      return pattern;
    }
  }
}
