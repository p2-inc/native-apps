package io.phasetwo.keycloak.nativeauth.sdk.passkeys

/** A username and password from the user's password manager. [toString] leaves the password out. */
public class SavedPassword(public val username: String, public val password: String) {
  override fun equals(other: Any?): Boolean = other is SavedPassword && other.username == username && other.password == password

  override fun hashCode(): Int = 31 * username.hashCode() + password.hashCode()

  override fun toString(): String = "SavedPassword(username=$username, password=***)"
}

/**
 * The platform half of password-manager support: [pick] shows the system sheet of passwords saved
 * for the app (Google Password Manager and third-party providers), [save] offers to store the ones
 * the user typed after a successful sign-in. The `android` module provides one over Credential
 * Manager; tests inject a mock.
 *
 * Closing the sheet must surface as `saved_password_cancelled`; nothing saved, no provider or no
 * sheet as `saved_password_unavailable`. Neither is a flow failure.
 */
public interface SavedPasswordPlatform {
  public suspend fun pick(): SavedPassword

  public suspend fun save(password: SavedPassword)
}
