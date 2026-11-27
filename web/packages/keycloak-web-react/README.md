# @p2-inc/keycloak-web-react

Unstyled React components and hooks for signing users in to Keycloak without a redirect, on [`@p2-inc/keycloak-web`](https://www.npmjs.com/package/@p2-inc/keycloak-web).

```tsx
import { KeycloakProvider, SignIn, StepUpBoundary, useKeycloak } from '@p2-inc/keycloak-web-react';

<KeycloakProvider kc={kc}>
  <StepUpBoundary>
    <SignIn components={{ password: MyPasswordScreen }} />
  </StepUpBoundary>
</KeycloakProvider>;
```

No CSS: style the `data-kc-part` hooks, replace any challenge's component, or build your own UI with `useLogin()`. Guide: [docs/web-integration.md](https://github.com/p2-inc/native-apps/blob/main/docs/web-integration.md). Apache-2.0.
