import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { LoginResult } from '@p2-inc/keycloak-web';
import { KeycloakProvider, SignIn, useKeycloak, type ChallengeProps } from '../src';
import { DEMO, DEMO_ALT, IT_PARAMETERS, replay } from '../../keycloak-web/test/support';

afterEach(cleanup);

function type(label: RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function submitForm() {
  const form = document.querySelector('form[data-kc-part="form"]');
  if (form === null) throw new Error('no form');
  fireEvent.submit(form);
}

function Status() {
  const { isAuthenticated, user } = useKeycloak();
  return <p data-testid="status">{isAuthenticated ? `in:${String(user?.preferred_username)}` : 'out'}</p>;
}

describe('<SignIn>', () => {
  it('walks username, password and TOTP and signs the user in', async () => {
    const { kc, transport } = replay(['NativeAuthIT.happyPathUsernamePasswordTotpYieldsTokensWithoutRedirectUri'], DEMO, {
      range: [1, 5],
    });
    const results: LoginResult[] = [];
    render(
      <KeycloakProvider kc={kc}>
        <Status />
        <SignIn parameters={IT_PARAMETERS} onResult={(r) => results.push(r)} />
      </KeycloakProvider>
    );
    expect(screen.getByTestId('status').textContent).toBe('out');

    await screen.findByLabelText(/username/i);
    expect(screen.getByLabelText(/username/i).getAttribute('autocomplete')).toBe('username');
    type(/username/i, 'alice');
    await act(async () => submitForm());

    await screen.findByLabelText(/^password$/i);
    expect(screen.getByText('Signing in as Alice Example')).toBeTruthy();
    expect(screen.getByLabelText(/^password$/i).getAttribute('autocomplete')).toBe('current-password');
    type(/^password$/i, 'alice-password');
    await act(async () => submitForm());

    await screen.findByLabelText(/code/i);
    expect(screen.getByLabelText(/code/i).getAttribute('autocomplete')).toBe('one-time-code');
    type(/code/i, '000000');
    await act(async () => submitForm());

    await waitFor(() => expect(results.length).toBe(1));
    if (results[0]!.kind === 'failed') throw results[0]!.error;
    await waitFor(() => expect(screen.getByTestId('status').textContent).toBe('in:alice'));
    expect(document.querySelector('[data-kc-root]')?.getAttribute('data-kc-phase')).toBe('finished');
    expect(transport.remaining).toBe(0);
  });

  it('shows the server error on the challenge and keeps the form', async () => {
    const { kc } = replay(['NativeAuthIT.wrongPasswordRechallengesWithErrorDescriptorThenSucceeds'], DEMO);
    render(
      <KeycloakProvider kc={kc}>
        <SignIn parameters={IT_PARAMETERS} />
      </KeycloakProvider>
    );
    type(await screen.findByLabelText(/username/i).then(() => /username/i), 'alice');
    await act(async () => submitForm());
    await screen.findByLabelText(/^password$/i);
    type(/^password$/i, 'wrong');
    await act(async () => submitForm());
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBeTruthy();
    expect(screen.getByLabelText(/^password$/i).getAttribute('aria-invalid')).toBe('true');
  });

  it('lets an app replace one challenge component and lists the alternatives', async () => {
    const { kc } = replay(['NativeAuthIT.q2_alternativesAreOfferedTogetherAndEitherCanBeAnswered'], DEMO_ALT);
    function MyPassword({ challenge }: ChallengeProps<'password'>) {
      return <p data-testid="custom">custom {challenge.wireType}</p>;
    }
    render(
      <KeycloakProvider kc={kc}>
        <SignIn parameters={IT_PARAMETERS} components={{ password: MyPassword }} />
      </KeycloakProvider>
    );
    type(await screen.findByLabelText(/username/i).then(() => /username/i), 'alice');
    await act(async () => submitForm());
    const alternatives = document.querySelector('[data-kc-part="alternatives"]');
    // Whatever the first entry is, the set offers at least one other way in.
    await waitFor(() => expect(document.querySelector('[data-kc-part="alternatives"]')).not.toBeNull());
    void alternatives;
    const buttons = [...document.querySelectorAll<HTMLButtonElement>('[data-kc-part="alternative"]')];
    const password = buttons.find((b) => b.dataset.kcChallenge === 'password');
    if (password) {
      fireEvent.click(password);
      expect((await screen.findByTestId('custom')).textContent).toBe('custom password');
    } else {
      expect(screen.getByTestId('custom')).toBeTruthy();
    }
  });
});
