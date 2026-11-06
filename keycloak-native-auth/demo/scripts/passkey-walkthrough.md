# Passkey walkthrough (HTTP sequence)

`walkthrough.sh` covers username → password → TOTP with curl. Passkeys need a WebAuthn signer for
the assertion and the attestation, which `openssl` one-liners cannot produce, so this file lists the
requests and points at the Java simulator the integration tests use
(`src/test/java/.../SoftwareAuthenticator.java`, driven by `PasskeyIT`). Base: `B=$KC_BASE/realms/demo`
(`KC_BASE=http://localhost:8089` when the stack runs on that port).

All binary values are base64url without padding. Field names are the ones of `spec/03-protocol-spec.md`.

## A. Register a passkey after a normal login (spec/03 §6)

1. Log in with `walkthrough.sh` (or any native login) and keep `ACCESS_TOKEN`. The token must be less
   than `native-auth.passkey-registration-max-age` seconds (default 300) past the authentication.
2. Options:
   ```bash
   curl -s -X POST "$B/native-auth/passkey/register/options" -H "Authorization: Bearer $ACCESS_TOKEN"
   # -> 200 { registration_id, challenge, rp:{id,name}, user:{id,name,display_name},
   #          pub_key_cred_params:[{type,alg}], authenticator_selection:{...}, attestation, exclude_credentials, timeout }
   ```
3. Create the credential with the platform API (`ASAuthorizationPlatformPublicKeyCredentialProvider`
   on iOS; in tests `SoftwareAuthenticator.register(challenge, user.id)`).
4. Finish:
   ```bash
   curl -s -X POST "$B/native-auth/passkey/register/finish" -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"registration_id":"…","credential_id":"…","client_data_json":"…","attestation_object":"…","transports":"internal,hybrid","label":"My iPhone"}'
   # -> 201 { "credential_id": "…", "label": "My iPhone" }
   ```
   `401 invalid_token`: no/invalid token. `403 insufficient_authorization`: log in again first.
   `400 invalid_request`: bad body, used/expired `registration_id`, or the attestation did not verify.

## B. Log in with the passkey (spec/03 §4.3)

Client `demo-native` (flow `native`): after `username`, the set is `[passkey, password]` once the user
has a passkey:

```bash
# start + username exactly as in walkthrough.sh, then:
#   challenges[0] = { type: "passkey", id: E2, params: { challenge, rp_id: "localhost", timeout,
#                     user_verification: "required", allow_credentials: [{type,id,transports}], discoverable: false } }
curl -s -X POST "$B/native-auth/challenge" -d auth_session="$S" -d challenge_type=passkey -d challenge_id="$E2" \
  -d credential_id=… -d client_data_json=… -d authenticator_data=… -d signature=… -d user_handle=…
# -> 403 totp challenge (alice) or 200 { authorization_code, auth_session } (users without a second factor)
```

Client `demo-native-passkey` (flow `native-passkey-first`): the **first** response already offers
`[passkey (discoverable: true, allow_credentials: []), username]`; answer `passkey` with a resident
credential (the `user_handle` names the user) or `username` to fall back to password.

`client_data_json.origin` must be Keycloak's base origin (`http://localhost:8089` for the compose
stack) or one of the Passwordless policy's extra origins; `rp_id` is `localhost` in the demo realm.

## C. Enrol a passkey during the first login (required action, spec/03 §4.4)

User `dave` / `dave-password` carries the `native-passkey-register` required action:

```bash
# start -> username=dave -> password=dave-password ->
# 403 { challenges: [ { type: "passkey_registration", id: "native-passkey-register", required: true,
#                       params: { challenge, rp, user, pub_key_cred_params, authenticator_selection, attestation, exclude_credentials, timeout } } ] }
curl -s -X POST "$B/native-auth/challenge" -d auth_session="$S" -d challenge_type=passkey_registration \
  -d challenge_id=native-passkey-register -d credential_id=… -d client_data_json=… -d attestation_object=… \
  -d transports=internal,hybrid -d label="Dave's phone"
# -> 200 { authorization_code, auth_session }; the action is removed and the next login offers the passkey
```

A failed attestation re-challenges with `error.code = invalid_attestation` and a fresh `challenge`.

## D. Reset

`docker compose down -v` drops the registered passkeys together with the database.
