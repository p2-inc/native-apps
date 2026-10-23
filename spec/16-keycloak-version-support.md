# 16 — Keycloak version support (26.4, 26.6, 26.8)

**Date:** 23 October 2026
**Supersedes:** 08 Q4 / 09 Q4 ("26.8.x floor"). The build target stays 26.8.1.
**Code:** `native-auth-core` (`compat/KeycloakCompat`, `AuthSessionCodec`), `native-auth-endpoint` (`ServicesCompat`, `CodeIssuer`, `RedirectToWebBuilder`), `native-auth-authenticators` (`NativeUsernameAuthenticator`), `native-auth-required-actions` (`WebAuthnCompat`, `PasskeyRegistrationOptions`, `PasskeyRegistrationVerifier`), `demo` (`KeycloakContainerSupport`), `.github/workflows/ci.yml`
**Evidence:** `mvn verify -Dkeycloak.image=quay.io/keycloak/keycloak:<v>` for 26.4.5, 26.6.4 and 26.8.1 with JARs compiled against 26.8.1: 58/58 ITs on each (26.6.4: `StepUpIT`'s idle-timeout test needs the wider margins of the separate CI fix, then 6/6); `AuthSessionCodecTest.portableEncryptionMatchesKeycloaksJweDirectEncode`.

## Why the floor moved

An integrator ran the extensions on 26.4 and needed seven source changes. Supporting 26.4 and 26.6 costs one small compat layer; the 26.8 floor of 09 Q4 was set before anyone had run another version, not because a feature required it.

## D1 — One build, resolved at runtime

The extensions compile against the newest supported version (26.8.1) and nothing else; there are no per-version builds or classifiers. Every member an older version lacks goes through a module-local compat class that resolves it once by reflection, with the older behaviour as the fallback:

| Difference | 26.4 | 26.6 | 26.8 | Where |
|---|---|---|---|---|
| `OAuth2Code` constructor | 9 args | 10 (`+ resource`) | 11 (`+ clientId`) | `ServicesCompat.newOAuth2Code` (by parameter count) |
| PAR single-use key | `key` | `"par:" + key` | `buildCacheKey(realmId, key)` = `"par:<realm>:" + key` | `ServicesCompat.parCacheKey` |
| `ParEndpoint.PAR_CLIENT_ID` | — | — | issuing client, checked by the authorization endpoint | `ServicesCompat.putParClientId` (older versions must not receive it: it would become a request parameter) |
| `ParEndpoint.REQUEST_URI_PREFIX` | private | public | public | `KeycloakCompat.PAR_REQUEST_URI_PREFIX` (RFC 9126 constant) |
| `AuthenticatorUtils.isUsernameTooLong` | — | — | yes | `KeycloakCompat.isUsernameTooLong` (`varchar(255)`) |
| `WebAuthnPolicy.getResidentKey` | — | — | yes | `WebAuthnCompat.residentKey` (else `getRequireResidentKey`: `Yes` → `required`, `No` → `discouraged`) |
| `KeycloakTrustAnchorRepository` | — | — | yes | `WebAuthnCompat.trustAnchors` (else webauthn4j `KeyStoreTrustAnchorRepository` over the server truststore, Keycloak 26.4's own construction) |
| `TokenUtil.jweDirectEncode(kid, …)` | — | yes | yes | not a compat call: `AuthSessionCodec.encryptDirect` builds the identical JWE (`alg=dir`, AES-GCM by key size, `kid`) from `JWE` primitives present in all three, so tokens are interchangeable |

Compile-time constants that exist in all three (`PAR_CREATED_TIME`, `PAR_DPOP_PROOF_JKT`) are inlined by javac and need nothing. webauthn4j differs too (0.29.3 in 26.4/26.6, 0.30.3 in 26.8); every webauthn4j class the extensions import exists in 0.29.3, and the ITs (passkey login and registration, recovery, enrol-on-first-login) pass on it.

**Rule.** No class outside `KeycloakCompat` / `ServicesCompat` / `WebAuthnCompat` may call a member that one of the supported versions lacks. A new difference is found by the CI matrix (D3), not by review.

## D2 — Realm exports target the newest version

The demo export stays written for 26.8 (it uses `webAuthnPolicyPasswordlessResidentKey`, which the 26.4/26.6 importers reject). `KeycloakContainerSupport.realmExportFor` strips fields newer than the image's version (`FIELDS_SINCE`) before the import; the export also carries `webAuthnPolicyPasswordlessRequireResidentKey: Yes`, which older versions read, so the descriptors (and transcripts) are identical on all three.

## D3 — CI matrix

`build-and-test` runs `mvn verify` once per supported minor with `-Dkeycloak.image`: `26.8.1`, `26.6.4` (the newest 26.6 published to Maven Central / quay at the time) and `26.4.5`; `fail-fast: false`. Transcripts are recorded from the 26.8.1 run only (`update-transcripts.sh`).

## Not done

- A Keycloak nightly job (allowed to fail) and versions older than 26.4.
- The integrator's hand-written JWE was not taken as is: building the same JWE as Keycloak's helper keeps tokens decryptable across a rolling upgrade between versions.
