# @p2-inc/keycloak-web

Sign users in to Keycloak from a single-page app without a redirect: the [native-apps](https://github.com/p2-inc/native-apps) challenge protocol in the browser, with DPoP (a non-extractable WebCrypto key), passkeys with autofill, step-up, application-initiated actions and a popup fallback for steps without a native variant.

```ts
import { KeycloakWeb } from '@p2-inc/keycloak-web';

const kc = KeycloakWeb.configure({ issuer: 'https://auth.example.com/realms/acme', clientId: 'acme-web' });
await kc.restore(); // a reload keeps the session

const flow = await kc.authentication().startLogin();
let step = await flow.start(); // { kind: 'challenges' | 'authorized' | 'redirectToWeb' }

const response = await kc.fetch('https://api.example.com/me'); // DPoP-bound token, RFC 9470 step-up
```

React components: [`@p2-inc/keycloak-web-react`](https://www.npmjs.com/package/@p2-inc/keycloak-web-react). Server: the native-auth Keycloak extensions. Guide: [docs/web-integration.md](https://github.com/p2-inc/native-apps/blob/main/docs/web-integration.md). Apache-2.0.
