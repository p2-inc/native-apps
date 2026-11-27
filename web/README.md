# Web SDK

Sign users in to Keycloak from a single-page app with the app's own screens, over the same challenge protocol as the native SDKs ([spec/22](../spec/22-web-sdk.md)). npm workspaces:

| Directory | Package | What |
| --- | --- | --- |
| [`packages/keycloak-web`](packages/keycloak-web) | `@p2-inc/keycloak-web` | Framework-free core: the login flow, tokens and DPoP, passkeys, the popup fallback, step-up for `fetch`, and `LoginController` for any UI |
| [`packages/keycloak-web-react`](packages/keycloak-web-react) | `@p2-inc/keycloak-web-react` | Hooks and unstyled React components (`<SignIn>`, `<StepUp>`, `<RequiredAction>`, `<StepUpBoundary>`) |
| [`demo`](demo) | (private) | Vite app against the compose demo realm |

```bash
npm install
npm run typecheck
npm test          # the core replays ../keycloak-native-auth/demo/transcripts
npm run build
npm run dev --workspace keycloak-web-demo   # http://localhost:5173, needs `docker compose up` in keycloak-native-auth/demo
```

Guide: [docs/web-integration.md](../docs/web-integration.md).
