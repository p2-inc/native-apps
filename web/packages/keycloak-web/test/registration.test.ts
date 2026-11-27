/** Registration and forgotten-password reset (spec/22 phase 3), replayed from RegistrationIT. */
import { describe, expect, it } from 'vitest';
import { LoginController, accessTokenClaims, parseMetadata } from '../src';
import { DEMO, IT_PARAMETERS, authorized, exchange, loadTranscript, replay, requireChallenge, types } from './support';

describe('registration', () => {
  it('metadata lists the flows the realm allows', () => {
    const t = loadTranscript('RegistrationIT.metadataAdvertisesRegistrationAndReset');
    expect(parseMetadata(exchange(t, 1).response.json).flowsSupported).toEqual(['login', 'registration', 'reset_credentials']);
    expect(parseMetadata({ protocol_version: '1', authorization_challenge_endpoint: 'x', token_endpoint: 'y' }).flowsSupported).toEqual(['login']);
  });

  it('the registration challenge describes the user profile and returns field errors', async () => {
    const { kc, transport } = replay(['RegistrationIT.fieldErrorsComeBackOnTheRegistrationChallenge'], DEMO);
    const flow = await kc.authentication().startLogin({ ...IT_PARAMETERS, flow: 'registration' });
    let step = await flow.start();
    const registration = requireChallenge(step, 'registration');
    expect(registration.params.attributes.map((a) => a.name)).toEqual(['username', 'email', 'firstName', 'lastName']);
    const email = registration.params.attributes[1]!;
    expect(email.displayName).toBe('Email');
    expect(email.required).toBe(true);
    expect(Object.keys(email.validators)).toContain('email');
    expect(registration.params.emailAsUsername).toBe(false);

    step = await flow.respond(
      {
        kind: 'registration',
        attributes: { username: 'bob', email: 'not-an-email', firstName: 'Rhea', lastName: 'Example' },
        password: 'x',
        confirm: 'y',
      },
      registration
    );
    const again = requireChallenge(step, 'registration');
    expect(again.error?.code).toBe('invalid_profile');
    expect(again.params.fieldErrors).toEqual({
      email: ['Invalid email address.'],
      username: ['Username already exists.'],
      password_confirm: ["Passwords don't match."],
    });
    expect(transport.remaining).toBe(0);
  });

  it('rhea registers and is signed in', async () => {
    const { kc, transport } = replay(['RegistrationIT.rheaRegistersAndIsSignedIn'], DEMO, { range: [1, 3] });
    const controller = new LoginController(kc, { mode: { kind: 'registration', parameters: IT_PARAMETERS } });
    await controller.start();
    const phase = controller.state.phase;
    if (phase.kind !== 'challenges' || phase.selected.type !== 'registration') throw new Error('expected registration');
    await controller.submit(
      {
        kind: 'registration',
        attributes: { username: 'rhea', email: 'rhea@example.com', firstName: 'Rhea', lastName: 'Example' },
        password: 'rhea-password-1',
        confirm: 'rhea-password-1',
      },
      phase.selected
    );
    const done = controller.state.phase;
    expect(done.kind === 'finished' && done.result.kind).toBe('authorized');
    expect(accessTokenClaims(kc.credentialsManager().snapshot!)?.preferred_username).toBe('rhea');
    expect(transport.remaining).toBe(0);
  });
});

describe('forgot password', () => {
  it('username, emailed code, new password, signed in', async () => {
    const { kc, transport } = replay(['RegistrationIT.rheaResetsHerPasswordWithAnEmailedCode'], DEMO, { range: [1, 6] });
    const flow = await kc.authentication().startLogin({ ...IT_PARAMETERS, flow: 'reset_credentials' });
    let step = await flow.start();
    expect(types(step)).toEqual(['username']);
    step = await flow.respond({ kind: 'username', username: 'rhea@example.com' }, requireChallenge(step, 'username'));
    const otp = requireChallenge(step, 'otp');
    expect(otp.params.sent).toBe(true);
    expect(otp.params.destinationMasked).toBe('r***@example.com');
    step = await flow.respond({ kind: 'otp', code: '000000' }, otp);
    expect(requireChallenge(step, 'otp').error?.code).toBe('invalid_credential');
    step = await flow.respond({ kind: 'otp', code: '123456' }, requireChallenge(step, 'otp'));
    const update = requireChallenge(step, 'update_password');
    step = await flow.respond({ kind: 'updatePassword', password: 'rhea-password-2', confirm: 'rhea-password-2' }, update);
    expect(accessTokenClaims(authorized(step).credentials)?.preferred_username).toBe('rhea');
    expect(transport.remaining).toBe(0);
  });
});
