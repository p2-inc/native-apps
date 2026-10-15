package io.phasetwo.keycloak.nativeauth.core.push;

import io.phasetwo.keycloak.nativeauth.core.model.Metadata;
import java.net.URI;
import java.util.Map;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

/**
 * Bridge to the push-MFA extension (spec/03 §1.1 {@code push} block, §7 step (b), spec/14 D9),
 * implemented by {@code native-auth-push}. The endpoint module looks it up through the SPI so it
 * does not depend on the push-MFA classes: when no provider is installed the metadata has no
 * {@code push} block and {@code /push/enroll/start} answers {@code 404}.
 */
public interface NativePushEnrolmentProvider extends Provider {

  /** The metadata block for this realm. */
  Metadata.Push metadata(RealmModel realm, URI baseUri);

  /**
   * Creates an enrolment challenge for {@code user} and returns the §7 (b) body: {@code
   * enrollment_token}, {@code expires_in}, {@code device_api_base}, {@code user_id}.
   */
  Map<String, Object> start(RealmModel realm, UserModel user, ClientModel client, URI baseUri);

  @Override
  default void close() {}
}
