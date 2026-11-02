package io.phasetwo.keycloak.nativeauth.sdk.logging

public enum class LogLevel { DEBUG, INFO, WARNING, ERROR }

/**
 * Logging hook (spec/05 §3.3). Everything the SDK logs has already gone through [Redactor];
 * implementations must not try to log raw requests themselves. [message] is evaluated only when
 * the implementation calls it, so a filtering logger pays nothing for debug lines.
 */
public fun interface NativeAuthLogger {
  public fun log(level: LogLevel, message: () -> String)
}

/** Discards everything. The `android` module supplies a Logcat logger. */
public object NoopLogger : NativeAuthLogger {
  override fun log(level: LogLevel, message: () -> String) {}
}
