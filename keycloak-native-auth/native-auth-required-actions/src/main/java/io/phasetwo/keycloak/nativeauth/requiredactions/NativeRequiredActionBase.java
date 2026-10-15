package io.phasetwo.keycloak.nativeauth.requiredactions;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequestContext;
import io.phasetwo.keycloak.nativeauth.core.spi.NativeRequiredAction;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.KeycloakSession;

/**
 * Shared behaviour of the native required actions (spec/03 §4.11): outside a native authentication
 * session the action ignores itself (a browser login shows Keycloak's own page, if the action is
 * one of Keycloak's); inside one, {@link #emit} hands a single descriptor to the endpoint.
 */
public abstract class NativeRequiredActionBase implements NativeRequiredAction {

  protected final Logger log = Logger.getLogger(getClass());
  protected final KeycloakSession session;

  protected NativeRequiredActionBase(KeycloakSession session) {
    this.session = session;
  }

  protected abstract String providerId();

  @Override
  public void evaluateTriggers(RequiredActionContext context) {}

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    if (!NativeRequestContext.isNative(context.getAuthenticationSession())) {
      log.warnf(
          "Required action '%s' is only served by the native challenge endpoint; ignoring it for a non-native login of user %s",
          providerId(), context.getUser().getUsername());
      context.ignore();
      return;
    }
    challenge(context, null);
  }

  /** Builds and emits the descriptor; {@code error} describes the previous attempt. */
  protected abstract void challenge(RequiredActionContext context, ChallengeDescriptor.ChallengeError error);

  protected void emit(RequiredActionContext context, ChallengeDescriptor descriptor) {
    descriptor.setRequired(true);
    NativeRequestContext.setPendingRequiredAction(context.getAuthenticationSession(), providerId(), descriptor);
    NativeRequestContext.envelope(session).replaceAll(List.of(descriptor));
    context.challenge(NativeRequestContext.markerResponse());
  }

  protected static MultivaluedMap<String, String> form(RequiredActionContext context) {
    MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
    return form == null ? new MultivaluedHashMap<>() : form;
  }

  protected static String param(RequiredActionContext context, String name) {
    String value = form(context).getFirst(name);
    return value == null ? null : value.trim();
  }

  protected static boolean isBlank(String s) {
    return s == null || s.isEmpty();
  }

  @Override
  public void close() {}
}
