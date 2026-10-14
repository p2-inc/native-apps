package io.phasetwo.keycloak.nativeauth.otp;

import org.keycloak.provider.ProviderFactory;

/** Factory of a {@link NativeOtpSender}; the id is the channel name used in the authenticator config. */
public interface NativeOtpSenderFactory extends ProviderFactory<NativeOtpSender> {}
