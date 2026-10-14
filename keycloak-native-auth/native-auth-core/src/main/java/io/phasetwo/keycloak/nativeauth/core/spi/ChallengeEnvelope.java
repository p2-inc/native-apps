package io.phasetwo.keycloak.nativeauth.core.spi;

import io.phasetwo.keycloak.nativeauth.core.model.ChallengeDescriptor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Per-request accumulator of challenge descriptors. Authenticators fill it; the endpoint reads it once
 * the {@code AuthenticationProcessor} returns the marker response (spec/04 §2.1).
 */
public final class ChallengeEnvelope {

  private final List<ChallengeDescriptor> challenges = new ArrayList<>();

  public void add(ChallengeDescriptor descriptor) {
    challenges.add(descriptor);
  }

  public void replaceAll(List<ChallengeDescriptor> descriptors) {
    challenges.clear();
    challenges.addAll(descriptors);
  }

  public List<ChallengeDescriptor> challenges() {
    return Collections.unmodifiableList(challenges);
  }

  public boolean isEmpty() {
    return challenges.isEmpty();
  }
}
