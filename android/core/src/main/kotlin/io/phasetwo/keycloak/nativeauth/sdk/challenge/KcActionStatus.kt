package io.phasetwo.keycloak.nativeauth.sdk.challenge

/** Outcome of an application-initiated action (spec/21, `kc_action_status` in the success body). */
public sealed class KcActionStatus {
  public abstract val wire: String

  /** The action completed. */
  public object Success : KcActionStatus() {
    override val wire: String = "success"
  }

  /** The user declined it (`action=skip`). */
  public object Cancelled : KcActionStatus() {
    override val wire: String = "cancelled"
  }

  /** The server could not run it: unknown alias, disabled, or not allowed to be started by the app. */
  public object Error : KcActionStatus() {
    override val wire: String = "error"
  }

  /** A value this SDK version does not know. */
  public data class Other(override val wire: String) : KcActionStatus()

  override fun toString(): String = wire

  public companion object {
    public fun fromWire(wire: String): KcActionStatus =
      when (wire) {
        "success" -> Success
        "cancelled" -> Cancelled
        "error" -> Error
        else -> Other(wire)
      }
  }
}
