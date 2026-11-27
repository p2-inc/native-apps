import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { KeycloakWeb, NativeAuthError } from '@p2-inc/keycloak-web';
import {
  KeycloakProvider,
  RequiredAction,
  SignIn,
  StepUp,
  StepUpBoundary,
  useKeycloak,
} from '@p2-inc/keycloak-web-react';
import './styles.css';

// The demo realm (keycloak-native-auth/demo): `docker compose up` serves it on :8080, with the
// `demo-web` client allowing this page's origin.
const kc = KeycloakWeb.configure({
  issuer: import.meta.env.VITE_KEYCLOAK_ISSUER ?? 'http://localhost:8080/realms/demo',
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID ?? 'demo-web',
});

// For poking at the SDK from the console during development.
if (import.meta.env.DEV) (window as unknown as { kc: KeycloakWeb }).kc = kc;

// The demo realm's step-up API (docker compose): /transfer needs acr 2 and answers RFC 9470 otherwise.
const resourceServer = import.meta.env.VITE_RESOURCE_SERVER ?? 'http://localhost:8091';

type Panel = { kind: 'none' } | { kind: 'action'; alias: string; title: string } | { kind: 'stepUp' };

function Home() {
  const { isAuthenticated, restoring, user, signOut, credentials } = useKeycloak();
  const [panel, setPanel] = useState<Panel>({ kind: 'none' });
  const [message, setMessage] = useState<string>();

  if (restoring) return <p className="muted">Restoring your session…</p>;
  if (!isAuthenticated) {
    return (
      <section className="card">
        <SignIn title="Sign in to the demo" />
        <p className="muted small">
          Try <code>alice</code> / <code>alice-password</code> (TOTP), <code>bob</code> / <code>bob-password</code>, or{' '}
          <code>carol</code>, who must update her password.
        </p>
      </section>
    );
  }

  const addPasskey = async () => {
    setMessage(undefined);
    try {
      const passkey = await kc.registerNewPasskey('This browser');
      setMessage(`Passkey ${passkey.label ?? ''} added.`);
    } catch (e) {
      const error = NativeAuthError.from(e);
      if (error.code === 'insufficient_authorization') {
        // The login is older than the realm allows for adding a passkey: confirm it's you first.
        setPanel({ kind: 'stepUp' });
        setMessage('Confirm it is you, then add the passkey again.');
      } else if (error.code !== 'passkey_cancelled') {
        setMessage(error.errorDescription ?? error.code);
      }
    }
  };

  const transfer = async () => {
    setMessage(undefined);
    try {
      // kc.fetch adds the DPoP-bound token; on insufficient_user_authentication the
      // <StepUpBoundary> asks for the missing factor, then this request is retried.
      const response = await kc.fetch(`${resourceServer}/transfer`);
      const body = (await response.json()) as { status?: string; acr?: string; error_description?: string };
      setMessage(response.ok ? `Transfer ${body.status} at acr ${body.acr}.` : (body.error_description ?? `HTTP ${response.status}`));
    } catch (e) {
      setMessage(NativeAuthError.from(e).errorDescription ?? String(e));
    }
  };

  return (
    <section className="card">
      <h2>Hello, {String(user?.name ?? user?.preferred_username ?? 'there')}</h2>
      <dl className="facts">
        <dt>Token type</dt>
        <dd>{credentials?.tokenType}</dd>
        <dt>Expires</dt>
        <dd>{credentials ? new Date(credentials.expiresAt).toLocaleTimeString() : ''}</dd>
      </dl>
      <div className="actions">
        <button onClick={() => setPanel({ kind: 'action', alias: 'UPDATE_PASSWORD', title: 'Change your password' })}>
          Change password
        </button>
        <button onClick={() => void addPasskey()}>Add a passkey</button>
        <button onClick={() => setPanel({ kind: 'stepUp' })}>Confirm it's you</button>
        <button onClick={() => void transfer()}>Transfer (needs level 2)</button>
        <button className="ghost" onClick={() => void signOut()}>
          Sign out
        </button>
      </div>
      {message && <p className="notice">{message}</p>}
      {panel.kind === 'action' && (
        <div className="panel">
          <RequiredAction
            alias={panel.alias}
            title={panel.title}
            onResult={(r) => {
              setPanel({ kind: 'none' });
              setMessage(r.kind === 'authorized' ? `Action ${r.kcActionStatus ?? 'finished'}.` : `Action ${r.kind}.`);
            }}
          />
        </div>
      )}
      {panel.kind === 'stepUp' && (
        <div className="panel">
          <StepUp
            maxAge={0}
            title="Confirm it's you"
            onResult={(r) => {
              setPanel({ kind: 'none' });
              setMessage(r.kind === 'authorized' ? 'Confirmed.' : `Step-up ${r.kind}.`);
            }}
          />
        </div>
      )}
    </section>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <KeycloakProvider kc={kc}>
      <StepUpBoundary>
        <main>
          <h1>Keycloak web SDK</h1>
          <Home />
        </main>
      </StepUpBoundary>
    </KeycloakProvider>
  </StrictMode>
);
