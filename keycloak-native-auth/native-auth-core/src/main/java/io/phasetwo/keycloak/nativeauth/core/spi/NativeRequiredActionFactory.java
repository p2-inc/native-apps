package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeType;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Factory marker for {@link NativeRequiredAction}s: lets the endpoint recognise a pending required
 * action as native (and run it in-band instead of answering {@code access_denied}) and advertise its
 * challenge type in {@code challenge_types_supported}.
 *
 * <p>A native action may also <em>substitute</em> for one of Keycloak's own required actions
 * (spec/03 §4.11): when {@link #substitutesFor()} names the pending action's alias, the native
 * action is registered and enabled in the realm, and {@link #canServe} agrees, the endpoint serves
 * the Keycloak action through the native one and removes the Keycloak action on success.
 */
public interface NativeRequiredActionFactory extends RequiredActionFactory {

  ChallengeType challengeType();

  /**
   * @return the alias of the Keycloak required action this native action can serve in its place
   *     (e.g. {@code UPDATE_PASSWORD}), or {@code null} when it only runs under its own alias
   */
  default String substitutesFor() {
    return null;
  }

  /** Whether the action can be completed natively for {@code user} (e.g. the user has an e-mail). */
  default boolean canServe(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }
}
