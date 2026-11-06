# Security policy

This repository is login code: the Keycloak extensions decide who gets a session, and the SDKs hold tokens and device keys. Please report suspected vulnerabilities privately, not in a public issue or pull request.

## Reporting a vulnerability

Use GitHub's private reporting: the **Security** tab of this repository, then **Report a vulnerability**. If that isn't available to you, email support@phasetwo.io with "Security" in the subject.

Include what you can of the affected component (a Keycloak extension module, the iOS SDK, the Android SDK), the version or commit, the Keycloak version, steps to reproduce, and the impact you expect. We acknowledge reports within three business days and keep you updated until a fix ships. Please give us a reasonable chance to release a fix before you disclose anything publicly.

## Supported versions

The project is below 1.0, so fixes land on `main` and in the next release; older releases are not patched. The Keycloak extensions are tested against Keycloak 26.4, 26.6 and 26.8.

## Scope

In scope: the extensions in `keycloak-native-auth/`, the SDKs in `ios/` and `android/`, and the protocol in `spec/03-protocol-spec.md`. Weaknesses in a deployment's own configuration are the operator's responsibility; [docs/security.md](docs/security.md) lists what administrators and app developers must set up. Vulnerabilities in Keycloak itself go to the [Keycloak project](https://github.com/keycloak/keycloak/security/policy), and ones in the push MFA extension to [ba-itsys](https://github.com/ba-itsys/keycloak-push-mfa-extension).
