# Recorded wire transcripts (contract fixtures)

One JSON file per integration test method, written by `TranscriptRecorder` (in
`src/test/java/.../TranscriptRecorder.java`) during `mvn verify` and copied here by
`scripts/update-transcripts.sh`. They are the contract fixtures of the iOS SDK
(`ios/KeycloakNative`, `Tests/KeycloakNativeCoreTests/TranscriptReplayTests.swift` replays them
through a mock transport), and a readable record of what the server does (spec/03).

Format:

```json
{
  "test": "NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri",
  "recorded_at": "2026-10-14T14:36:33Z",
  "keycloak_image": "quay.io/keycloak/keycloak:26.8.1",
  "base_url": "http://localhost:64092",
  "masked_form_fields": ["client_secret", "code_verifier", "otp", "password", "recovery_code", "refresh_token", "token", "totp"],
  "exchanges": [
    { "seq": 1,
      "request":  { "method": "POST", "path": "/realms/demo/native-auth/challenge", "headers": { "...": "..." },
                    "form": { "client_id": "demo-ios", "...": "..." } },
      "response": { "status": 403, "headers": { "...": "..." }, "json": { "error": "insufficient_authorization", "...": "..." } } }
  ]
}
```

- Only requests to `/realms/demo/native-auth/**` and `/realms/demo/protocol/openid-connect/**` are
  recorded; admin API calls the tests make are not part of the contract.
- `request.form` holds form fields; `request.json` a JSON body (passkey `finish`); `response.json` the
  parsed body, verbatim. Values in `masked_form_fields` and the `Authorization`/`DPoP` headers are
  replaced by `***`.
- `auth_session`, codes and tokens are recorded verbatim: they are JWEs/JWTs under keys of a test
  container that no longer exists, so they are inert. `base_url` carries the container's random port;
  the SDK tests rebase on `path`.
- Per-run values (`code_challenge`, challenge ids, WebAuthn material) differ between recordings; the
  SDK's mock transport treats `code_challenge`/`device_id` as presence-only and replays the recorded
  WebAuthn responses through a scripted passkey platform so every other field matches exactly.

Refresh after a server change: `mvn verify && scripts/update-transcripts.sh`, then run the SDK tests.
