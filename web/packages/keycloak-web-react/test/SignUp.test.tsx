import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { KeycloakWeb, MemoryStore } from '@p2-inc/keycloak-web';
import { KeycloakProvider, SignIn, SignUp, useKeycloak } from '../src';
import { DEMO, IT_PARAMETERS, MockTransport, exchange, loadTranscript, replay } from '../../keycloak-web/test/support';

afterEach(cleanup);

function Status() {
  const { user } = useKeycloak();
  return <p data-testid="user">{String(user?.preferred_username ?? '')}</p>;
}

function type(name: string, value: string) {
  const input = document.querySelector<HTMLInputElement>(`input[name="${name}"]`);
  if (input === null) throw new Error(`no input ${name}`);
  fireEvent.change(input, { target: { value } });
}

async function submit() {
  const form = document.querySelector('form[data-kc-part="form"]');
  if (form === null) throw new Error('no form');
  await act(async () => fireEvent.submit(form));
}

describe('<SignUp>', () => {
  it('renders the user-profile fields and shows field errors', async () => {
    const { kc, transport } = replay(['RegistrationIT.fieldErrorsComeBackOnTheRegistrationChallenge'], DEMO);
    render(
      <KeycloakProvider kc={kc}>
        <SignUp parameters={IT_PARAMETERS} />
      </KeycloakProvider>
    );
    await screen.findByLabelText('Email');
    expect(screen.getByLabelText('First name').getAttribute('autocomplete')).toBe('given-name');
    expect(screen.getByLabelText('Email').getAttribute('type')).toBe('email');
    type('username', 'bob');
    type('email', 'not-an-email');
    type('firstName', 'Rita');
    type('lastName', 'Example');
    type('password', 'x');
    type('password_confirm', 'x');
    // The recorded attempt sent different passwords; type what the IT sent.
    type('password_confirm', 'y');
    // The submit button stays disabled while the passwords differ; submit the form directly, as the IT did.
    await submit();
    await screen.findByText('Username already exists.');
    expect(screen.getByText('Invalid email address.')).toBeTruthy();
    expect(transport.remaining).toBe(0);
  });

  it('creates the account and signs the user in', async () => {
    const { kc, transport } = replay(['RegistrationIT.ritaRegistersAndIsSignedIn'], DEMO, { range: [1, 3] });
    render(
      <KeycloakProvider kc={kc}>
        <Status />
        <SignUp parameters={IT_PARAMETERS} />
      </KeycloakProvider>
    );
    await screen.findByLabelText('Username');
    type('username', 'rita');
    type('email', 'rita@example.com');
    type('firstName', 'Rita');
    type('lastName', 'Example');
    type('password', 'rita-password-1');
    type('password_confirm', 'rita-password-1');
    await submit();
    await waitFor(() => expect(screen.getByTestId('user').textContent).toBe('rita'));
    expect(transport.remaining).toBe(0);
  });
});

describe('<SignIn> links', () => {
  it('offers "Create an account" and "Forgot password?" when the realm allows them, and switches in place', async () => {
    const metadata = exchange(loadTranscript('RegistrationIT.metadataAdvertisesRegistrationAndReset'), 1);
    const login = exchange(loadTranscript('NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'), 1);
    const registration = exchange(loadTranscript('RegistrationIT.fieldErrorsComeBackOnTheRegistrationChallenge'), 1);
    const transport = new MockTransport([metadata, login, registration]);
    const kc = KeycloakWeb.configure({
      issuer: 'http://localhost:1/realms/demo',
      clientId: DEMO,
      transport,
      storage: new MemoryStore(),
      onWarning: () => {},
    });
    render(
      <KeycloakProvider kc={kc}>
        <SignIn parameters={IT_PARAMETERS} />
      </KeycloakProvider>
    );
    await screen.findByLabelText(/username/i);
    expect(await screen.findByRole('button', { name: 'Forgot password?' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Create an account' }));
    await screen.findByLabelText('Email');
    expect(screen.getByRole('heading', { name: 'Create your account' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Back to sign in' })).toBeTruthy();
    expect(transport.remaining).toBe(0);
  });
});
