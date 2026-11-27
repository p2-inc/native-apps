# Integrating the web SDK

[Index](README.md) · [Protocol](protocol-and-flows.md) · [React Native integration](react-native-integration.md) · [Plan and decisions (spec/22)](../spec/22-web-sdk.md)

`@p2-inc/keycloak-web` signs users in to Keycloak from a single-page app with the app's own screens: no redirect, no iframe. It speaks the same challenge protocol as the iOS, Android, React Native and Flutter SDKs, so the login flow you build in the admin console (passwords, passkeys, one-time codes, push approval, PINs, required actions, step-up) runs unchanged. `@p2-inc/keycloak-web-react` adds hooks and unstyled React components on top.

Use it for **first-party** apps only. Redirecting to Keycloak's login page remains the right choice for third-party apps, because only Keycloak's own page shows the user which site they are typing their password into (see [spec/22 D13](../spec/22-web-sdk.md#1-decisions)).

## Requirements

- Keycloak 26.4 or later with the native-auth extensions of this release (the challenge endpoint answers CORS from this release on).
- A browser with WebCrypto, IndexedDB and `fetch` (every current browser) on `https` or `localhost`.
- React 18.2 or later for the React package.

## Configure the client

In the realm, create (or reuse) a public OpenID Connect client:

| Setting | Value |
| --- | --- |
| Client authentication | Off (public client) |
| Standard flow | On |
| PKCE method (Advanced) | S256 |
| Attribute `native-auth.enabled` | `true` |
| Web origins | Your app's origin, e.g. `https://app.example.com` |
| Valid redirect URIs | An exact callback on your origin, e.g. `https://app.example.com/callback.html` |
| Attribute `native-auth.web-fallback-redirect-uri` | The same callback, used by the popup fallback |

For passkeys, add your app's origin to **Authentication → Policies → Webauthn Passwordless Policy → Extra Origins**, and make the policy's **Relying Party ID** a parent domain of both hosts, e.g. `example.com` for `app.example.com` and `auth.example.com`. On Phase Two hosted clusters that means a custom domain for Keycloak on your own domain.

## Install

```bash
npm install @p2-inc/keycloak-web @p2-inc/keycloak-web-react
```

## Sign in with React

```tsx
import { KeycloakWeb } from '@p2-inc/keycloak-web';
import { KeycloakProvider, SignIn, StepUpBoundary, useKeycloak } from '@p2-inc/keycloak-web-react';

const kc = KeycloakWeb.configure({
  issuer: 'https://auth.example.com/realms/acme',
  clientId: 'acme-web',
});

function App() {
  const { isAuthenticated, restoring, user, signOut } = useKeycloak();
  if (restoring) return null;
  if (!isAuthenticated) return <SignIn onResult={(r) => console.log(r.kind)} />;
  return <button onClick={signOut}>Sign out {String(user?.name)}</button>;
}

export default () => (
  <KeycloakProvider kc={kc}>
    <StepUpBoundary>
      <App />
    </StepUpBoundary>
  </KeycloakProvider>
);
```

`KeycloakProvider` restores a stored session on mount (a reload keeps the user signed in) and finishes a full-page fallback that returned to the app. `<SignIn>` renders the flow Keycloak sends, one challenge at a time, with "Try another way" for the alternatives.

### Styling and replacing screens

The components ship without CSS. Every element carries a `data-kc-part` attribute (`root`, `title`, `form`, `field`, `label`, `input`, `error`, `submit`, `secondary`, `alternatives`, `alternative`, `cancel`, …) and forms carry `data-kc-challenge="<type>"`. Style them from your stylesheet; the [demo's stylesheet](../web/demo/src/styles.css) is a starting point.

Replace the screen of one challenge type and keep the rest:

```tsx
import type { ChallengeProps } from '@p2-inc/keycloak-web-react';

function MyPassword({ challenge, submit, isSubmitting }: ChallengeProps<'password'>) {
  // render your own form; call submit({ kind: 'password', password }) to answer
}

<SignIn components={{ password: MyPassword }} />;
```

Or take the whole layout with `render`, or drive the flow yourself with `useLogin()` (a `LoginController` and its state). Strings are English by default; pass `strings` to `KeycloakProvider` or a component to replace some or all of them.

## Sign-up and forgot password

When the realm allows them (**Realm settings → Login → User registration / Forgot password**) and has the `native-registration` / `native-reset-credentials` flows (module `native-auth-registration`), `<SignIn>` offers "Create an account" and "Forgot password?" and switches in place; `links={false}` hides them. `<SignUp>` and `<ResetPassword>` are the same views on their own.

- **Sign-up** shows the realm's user profile for registration (labels, required fields, select options) and a password; Keycloak validates it (duplicate username or email, the password policy) and the errors appear under their fields. Email verification and terms then run as usual, and the new user is signed in.
- **Forgot password** asks for the username or email, emails a code (the realm's SMTP settings), asks for a new password and signs the user in. It does not reveal whether an account exists.

Without React: `kc.authentication().startLogin({ flow: 'registration' })` or `{ flow: 'reset_credentials' }`; `(await kc.metadata()).flowsSupported` says what the realm allows.

## Step-up and app-initiated actions

- `<StepUp acrValues="2" />` asks only for what the requested level still needs; `<StepUp maxAge={0} />` asks for every factor again ("Confirm it's you").
- `<RequiredAction alias="UPDATE_PASSWORD" />` runs a required action for the signed-in user (also `VERIFY_EMAIL`, `webauthn-register-passwordless`, `phasetwo-configure-pin`); `onResult` carries `kcActionStatus` (`success`, `cancelled`, `error`).
- `kc.fetch(url, init)` calls your API with the user's token: `Authorization: DPoP …` plus a proof when the token is bound. When the API answers RFC 9470 `insufficient_user_authentication` (`WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="2"`), `<StepUpBoundary>` shows a step-up dialog and the request is retried once it succeeds.

## Passkeys

- **Sign in:** a `passkey` challenge shows "Continue with a passkey". When the flow offers a discoverable passkey next to the username, the username field also lists passkeys in its autofill (`autocomplete="username webauthn"`).
- **Add one after sign-in:** `await kc.registerNewPasskey('My laptop')`. When Keycloak answers `insufficient_authorization` (the login is older than the realm allows), run `<StepUp maxAge={0} />` and try again.

## The browser fallback

Steps without a native variant (an unsupported required action, an identity provider) end in `redirect_to_web`. `<SignIn>` then offers "Open window": Keycloak's page opens in a popup, and when it reaches your callback the popup closes and the app is signed in. Serve a callback page that calls `completeWebFallbackPopup()` (see [`web/demo/callback.html`](../web/demo/callback.html)). Until the SSO cookie session lands ([spec/22 phase 6](../spec/22-web-sdk.md#3-phases)), Keycloak's page asks the user to sign in again.

## Tokens and sessions

| What | Where |
| --- | --- |
| Access token, ID token | Memory |
| Refresh token, post-login `auth_session` | IndexedDB, bound by DPoP to the key below |
| DPoP private key | IndexedDB, a non-extractable `CryptoKey` (it cannot be read, only used by this origin) |

An embedded sign-in creates a Keycloak user session on the server but sets no Keycloak cookie in the browser. The refresh token keeps the user signed in until the realm's SSO idle or maximum lifetime ends that session. Refreshes are serialized across tabs, and every tab of the origin follows sign-in, refresh and sign-out. `kc.signOut()` revokes the refresh token (ending the Keycloak session) and forgets the key. Use `storage: 'memory'` to keep nothing across reloads.

Add your Keycloak origin to the page's Content Security Policy `connect-src`.

## Without React

```ts
const flow = await kc.authentication().startLogin({ scope: 'openid profile' });
let step = await flow.start();
// step.kind: 'challenges' | 'authorized' | 'redirectToWeb'
step = await flow.respond({ kind: 'username', username: 'alice' }, step.challenges[0]);
```

`new LoginController(kc, { onResult })` adds the UI behavior (which challenge to show, push polling, passkey autofill, the popup) for any framework; subscribe to it like a store.

## Try it

```bash
cd keycloak-native-auth && mvn -DskipTests -DskipITs package
cd demo && docker compose up --wait
cd ../../web && npm install && npm run dev --workspace keycloak-web-demo
```

Open `http://localhost:5173` and sign in as `alice` / `alice-password` (TOTP from `./scripts/walkthrough.sh`). For the step-up demo against the resource server, start the app with `VITE_KEYCLOAK_CLIENT_ID=demo-web-stepup`: `alice` signs in with her password, and "Transfer (needs level 2)" asks for the TOTP.
