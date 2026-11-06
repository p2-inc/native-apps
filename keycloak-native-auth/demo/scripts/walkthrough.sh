#!/usr/bin/env bash
# End-to-end transcript of spec/03 §11 against the demo realm, with no browser:
#   start -> username -> password -> totp -> authorization_code -> tokens.
# Requires: curl, jq, openssl. Exits 0 only if an access token for alice was obtained.
set -euo pipefail

KC_BASE="${KC_BASE:-http://localhost:8080}"
REALM="${REALM:-demo}"
CLIENT_ID="${CLIENT_ID:-demo-native}"
USERNAME="${USERNAME:-alice}"
PASSWORD="${PASSWORD:-alice-password}"
# Raw TOTP secret seeded for alice in realm-export/demo-realm.json (its UTF-8 bytes are the HMAC key).
TOTP_SECRET="${TOTP_SECRET:-alice-totp-secret-20261014}"
B="$KC_BASE/realms/$REALM"

for tool in curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

log()  { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# base64url without padding
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# RFC 6238 TOTP (SHA1, 6 digits, 30 s) using only openssl/od/printf.
totp() {
  local secret_hex counter counter_hex bin hmac offset part
  secret_hex=$(printf '%s' "$TOTP_SECRET" | od -An -tx1 | tr -d ' \n')
  counter=$(( $(date +%s) / 30 ))
  counter_hex=$(printf '%016x' "$counter")
  bin=""
  for ((i = 0; i < 16; i += 2)); do bin+="\\x${counter_hex:$i:2}"; done
  hmac=$(printf "$bin" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$secret_hex" | sed 's/^.*= *//')
  offset=$(( 16#${hmac:39:1} ))
  part=${hmac:$((offset * 2)):8}
  printf '%06d' $(( (16#$part & 0x7fffffff) % 1000000 ))
}

# POST to the challenge endpoint; prints "<status>\n<body>"
challenge() {
  curl -sS -o /tmp/native-auth-body.$$ -w '%{http_code}' -X POST "$B/native-auth/challenge" \
    -H 'Accept: application/json' "$@"
  echo
  cat /tmp/native-auth-body.$$
  rm -f /tmp/native-auth-body.$$
}

# Verify a 403 insufficient_authorization response offers the expected challenge type; sets S and CH_ID
expect_challenge() {
  local status="$1" body="$2" type="$3"
  [[ "$status" == "403" ]] || fail "expected 403, got $status: $body"
  [[ "$(jq -r .error <<<"$body")" == "insufficient_authorization" ]] || fail "unexpected error: $body"
  S=$(jq -r .auth_session <<<"$body")
  CH_ID=$(jq -r --arg t "$type" '.challenges[] | select(.type == $t) | .id' <<<"$body" | head -1)
  [[ -n "$CH_ID" && "$CH_ID" != "null" ]] || fail "no '$type' challenge offered: $body"
  echo "   challenges: $(jq -c '[.challenges[] | {type, id, required, error}]' <<<"$body")"
  echo "   auth_session: sha256[0:8]=$(printf '%s' "$S" | openssl dgst -sha256 | sed 's/^.*= *//' | cut -c1-8) expires_in=$(jq -r .expires_in <<<"$body")"
}

log "0. metadata  GET $B/native-auth/metadata"
META=$(curl -sS -f "$B/native-auth/metadata") || fail "metadata not reachable at $B (is docker compose up?)"
echo "$META" | jq .
[[ "$(jq -r .protocol_version <<<"$META")" == "1" ]] || fail "unexpected protocol_version"
REDIRECT_URI_REQUIRED=$(jq -r .code_exchange.redirect_uri_required <<<"$META")
CODE_REDIRECT_URI=$(jq -r '.code_exchange.redirect_uri // empty' <<<"$META")

log "1. start  (client_id=$CLIENT_ID, PKCE S256)"
CV=$(openssl rand 32 | b64url)
CC=$(printf '%s' "$CV" | openssl dgst -sha256 -binary | b64url)
R=$(challenge -d client_id="$CLIENT_ID" -d response_type=code -d scope='openid profile' \
      -d code_challenge="$CC" -d code_challenge_method=S256 -d device_name='walkthrough.sh')
expect_challenge "$(head -1 <<<"$R")" "$(tail -n +2 <<<"$R")" username

log "2. username -> $USERNAME"
R=$(challenge -d auth_session="$S" -d challenge_type=username -d challenge_id="$CH_ID" -d username="$USERNAME")
expect_challenge "$(head -1 <<<"$R")" "$(tail -n +2 <<<"$R")" password

log "3. password"
R=$(challenge -d auth_session="$S" -d challenge_type=password -d challenge_id="$CH_ID" --data-urlencode password="$PASSWORD")
STATUS=$(head -1 <<<"$R"); BODY=$(tail -n +2 <<<"$R")
if [[ "$STATUS" == "403" ]]; then
  expect_challenge "$STATUS" "$BODY" totp
  log "4. totp (computed locally from the seeded secret)"
  CODE=$(totp)
  R=$(challenge -d auth_session="$S" -d challenge_type=totp -d challenge_id="$CH_ID" -d totp="$CODE")
  STATUS=$(head -1 <<<"$R"); BODY=$(tail -n +2 <<<"$R")
fi
[[ "$STATUS" == "200" ]] || fail "expected 200 with authorization_code, got $STATUS: $BODY"
AUTH_CODE=$(jq -r .authorization_code <<<"$BODY")
[[ -n "$AUTH_CODE" && "$AUTH_CODE" != "null" ]] || fail "no authorization_code in: $BODY"
echo "   authorization_code received (${#AUTH_CODE} chars)"

log "5. token exchange (grant_type=authorization_code, PKCE verifier, redirect_uri_required=$REDIRECT_URI_REQUIRED)"
TOKEN_ARGS=(-d grant_type=authorization_code -d client_id="$CLIENT_ID" -d code="$AUTH_CODE" -d code_verifier="$CV")
if [[ "$REDIRECT_URI_REQUIRED" == "true" ]]; then TOKEN_ARGS+=(--data-urlencode redirect_uri="$CODE_REDIRECT_URI"); fi
TOKENS=$(curl -sS -X POST "$B/protocol/openid-connect/token" "${TOKEN_ARGS[@]}")
ACCESS_TOKEN=$(jq -r '.access_token // empty' <<<"$TOKENS")
[[ -n "$ACCESS_TOKEN" ]] || fail "token endpoint did not return an access_token: $TOKENS"
CLAIMS=$(cut -d. -f2 <<<"$ACCESS_TOKEN" | tr '_-' '/+' | awk '{ l=length($0)%4; if (l==2) print $0"=="; else if (l==3) print $0"="; else print $0 }' | openssl base64 -d -A)
echo "   token_type=$(jq -r .token_type <<<"$TOKENS") expires_in=$(jq -r .expires_in <<<"$TOKENS") scope=\"$(jq -r .scope <<<"$TOKENS")\""
echo "   access_token claims: $(jq -c '{iss, sub, preferred_username, azp, sid}' <<<"$CLAIMS")"
[[ "$(jq -r .preferred_username <<<"$CLAIMS")" == "$USERNAME" ]] || fail "token is not for $USERNAME"

log "SUCCESS: obtained tokens for $USERNAME without a browser"
