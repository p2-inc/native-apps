import { useEffect, useId, useState, type ComponentType, type FormEvent, type ReactNode } from 'react';
import {
  errorMessage,
  isChallengeLocked,
  millisUntil,
  type Challenge,
  type ChallengeAnswer,
  type ChallengeOf,
  type ChallengeType,
  type FlowContext,
  type LoginController,
  type LoginStrings,
} from '@p2-inc/keycloak-web';

/** What every challenge component gets. */
export interface ChallengeProps<T extends ChallengeType = ChallengeType> {
  challenge: ChallengeOf<T>;
  /** The whole set, for components that combine entries (a username field with a passkey button). */
  challenges: Challenge[];
  context: FlowContext;
  controller: LoginController;
  strings: LoginStrings;
  isSubmitting: boolean;
  submit: (answer: ChallengeAnswer) => Promise<void>;
}

/** One component per challenge type; `<SignIn components={{ password: MyPassword }}>` replaces one. */
export type ChallengeComponents = { [T in ChallengeType]: ComponentType<ChallengeProps<T>> };

// ---------------------------------------------------------------------------------------------
// Small unstyled building blocks. Every element carries `data-kc-part` so a stylesheet (or the
// shadcn registry's versions) can target it without class names.

export function Field(props: {
  label: string;
  name: string;
  type?: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete?: string;
  inputMode?: 'numeric' | 'text' | 'email';
  maxLength?: number;
  autoFocus?: boolean;
  disabled?: boolean;
  error?: string;
}) {
  const id = `kc${useId().replace(/:/g, '')}-${props.name}`;
  return (
    <div data-kc-part="field" data-kc-field={props.name} data-invalid={props.error ? '' : undefined}>
      <label data-kc-part="label" htmlFor={id}>
        {props.label}
      </label>
      <input
        data-kc-part="input"
        id={id}
        name={props.name}
        type={props.type ?? 'text'}
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        autoComplete={props.autoComplete}
        inputMode={props.inputMode}
        maxLength={props.maxLength}
        autoFocus={props.autoFocus}
        disabled={props.disabled}
        aria-invalid={props.error ? true : undefined}
        aria-describedby={props.error ? `${id}-error` : undefined}
      />
      {props.error && (
        <p data-kc-part="error" id={`${id}-error`} role="alert">
          {props.error}
        </p>
      )}
    </div>
  );
}

function Form(props: { type: string; onSubmit: () => void; children: ReactNode }) {
  return (
    <form
      data-kc-part="form"
      data-kc-challenge={props.type}
      noValidate
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        props.onSubmit();
      }}
    >
      {props.children}
    </form>
  );
}

function Submit(props: { label: string; disabled?: boolean }) {
  return (
    <button data-kc-part="submit" type="submit" disabled={props.disabled}>
      {props.label}
    </button>
  );
}

function Secondary(props: { label: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button data-kc-part="secondary" type="button" onClick={props.onClick} disabled={props.disabled}>
      {props.label}
    </button>
  );
}

function Description(props: { children: ReactNode }) {
  return <p data-kc-part="description">{props.children}</p>;
}

function challengeError(strings: LoginStrings, challenge: Challenge): string | undefined {
  const base = errorMessage(strings, challenge.error?.code, challenge.error?.message);
  const remaining = challenge.retry?.remaining;
  if (base !== undefined && remaining !== undefined) return `${base} ${strings.attemptsLeft(remaining)}`;
  return base;
}

/** Seconds until `instant` (epoch ms), ticking once a second. */
function useCountdown(instant: number | undefined): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (millisUntil(instant, now) <= 0) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [instant, now]);
  return Math.ceil(millisUntil(instant, now) / 1000);
}

function codeLength(digits: number): { inputMode: 'numeric'; maxLength: number; autoComplete: string } {
  return { inputMode: 'numeric', maxLength: digits, autoComplete: 'one-time-code' };
}

// ---------------------------------------------------------------------------------------------
// The default components

export function UsernameChallenge({ challenge, challenges, controller, strings, isSubmitting, submit }: ChallengeProps<'username'>) {
  const [username, setUsername] = useState(challenge.params.hint ?? '');
  const passkey = challenges.find((c): c is ChallengeOf<'passkey'> => c.type === 'passkey' && c.params !== undefined);
  return (
    <Form type="username" onSubmit={() => submit({ kind: 'username', username: username.trim() })}>
      <Field
        label={challenge.label ?? (challenge.params.allowEmail ? strings.usernameOrEmail : strings.username)}
        name="username"
        value={username}
        onChange={setUsername}
        // `webauthn` lets the browser list passkeys in this field's autofill (conditional mediation).
        autoComplete={passkey?.params?.discoverable ? 'username webauthn' : 'username'}
        autoFocus
        disabled={isSubmitting}
        error={challengeError(strings, challenge)}
      />
      <Submit label={strings.continue} disabled={isSubmitting || username.trim().length === 0} />
      {passkey && (
        <Secondary label={strings.continueWithPasskey} onClick={() => void controller.usePasskey(passkey)} disabled={isSubmitting} />
      )}
    </Form>
  );
}

export function PasswordChallenge({ challenge, context, strings, isSubmitting, submit }: ChallengeProps<'password'>) {
  const [password, setPassword] = useState('');
  return (
    <Form type="password" onSubmit={() => submit({ kind: 'password', password })}>
      {/* A username field password managers can pair the password with. */}
      {context.username && (
        <input data-kc-part="hidden-username" type="text" name="username" autoComplete="username" value={context.username} readOnly hidden />
      )}
      <Field
        label={challenge.label ?? strings.password}
        name="password"
        type="password"
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        autoFocus
        disabled={isSubmitting}
        error={challengeError(strings, challenge)}
      />
      <Submit label={strings.signIn} disabled={isSubmitting || password.length === 0} />
    </Form>
  );
}

export function TotpChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'totp'>) {
  const [code, setCode] = useState('');
  // Only with a choice to make: one authenticator needs no credential_id (as in the native SDKs).
  const choice = challenge.params.credentials.length > 1;
  const [credentialId, setCredentialId] = useState(choice ? challenge.params.credentials[0]?.id : undefined);
  return (
    <Form type="totp" onSubmit={() => submit({ kind: 'totp', code, ...(credentialId ? { credentialId } : {}) })}>
      <Description>{strings.enterTotp(challenge.params.digits)}</Description>
      {choice && (
        <select data-kc-part="select" value={credentialId} onChange={(e) => setCredentialId(e.target.value)} disabled={isSubmitting}>
          {challenge.params.credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </select>
      )}
      <Field
        label={challenge.label ?? strings.authenticatorCode}
        name="totp"
        value={code}
        onChange={setCode}
        {...codeLength(challenge.params.digits)}
        autoFocus
        disabled={isSubmitting}
        error={challengeError(strings, challenge)}
      />
      <Submit label={strings.verify} disabled={isSubmitting || code.length === 0} />
    </Form>
  );
}

export function OtpChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'otp'>) {
  const [code, setCode] = useState('');
  const p = challenge.params;
  const wait = useCountdown(p.resendAllowedAt);
  const destination = p.destinationMasked ?? '';
  return (
    <Form type="otp" onSubmit={() => (p.sent ? submit({ kind: 'otp', code }) : submit({ kind: 'otpResend' }))}>
      <Description>{p.sent ? strings.weSentCode(p.digits, destination) : strings.weCanSendCode(p.digits, destination)}</Description>
      {p.sent && (
        <Field
          label={challenge.label ?? (p.channel === 'sms' ? strings.textMessageCode : strings.emailCode)}
          name="otp"
          value={code}
          onChange={setCode}
          {...codeLength(p.digits)}
          autoFocus
          disabled={isSubmitting}
          error={challengeError(strings, challenge)}
        />
      )}
      {p.sent ? (
        <>
          <Submit label={strings.verify} disabled={isSubmitting || code.length === 0} />
          <Secondary
            label={wait > 0 ? strings.resendCodeIn(wait) : strings.resendCode}
            onClick={() => void submit({ kind: 'otpResend' })}
            disabled={isSubmitting || wait > 0}
          />
        </>
      ) : (
        <Submit label={strings.sendCode} disabled={isSubmitting || wait > 0} />
      )}
    </Form>
  );
}

export function PasskeyChallenge({ challenge, controller, strings, isSubmitting }: ChallengeProps<'passkey'>) {
  return (
    <div data-kc-part="form" data-kc-challenge="passkey">
      <Description>{challenge.label ?? strings.passkeyTitle}</Description>
      {challenge.error && (
        <p data-kc-part="error" role="alert">
          {challengeError(strings, challenge)}
        </p>
      )}
      <button data-kc-part="submit" type="button" disabled={isSubmitting || challenge.params === undefined} onClick={() => void controller.usePasskey(challenge)}>
        {strings.continueWithPasskey}
      </button>
    </div>
  );
}

export function PasskeyRegistrationChallenge({ challenge, controller, strings, isSubmitting, submit }: ChallengeProps<'passkey_registration'>) {
  const [label, setLabel] = useState('');
  return (
    <Form type="passkey_registration" onSubmit={() => void controller.registerPasskey(challenge, label.trim() || undefined)}>
      <Description>{challenge.label ?? strings.createAPasskey}</Description>
      <Field label={strings.passkeyName} name="label" value={label} onChange={setLabel} disabled={isSubmitting} error={challengeError(strings, challenge)} />
      <Submit label={strings.createPasskey} disabled={isSubmitting || challenge.params === undefined} />
      {challenge.skippable && <Secondary label={strings.notNow} onClick={() => void submit({ kind: 'skip' })} disabled={isSubmitting} />}
    </Form>
  );
}

export function PushChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'push'>) {
  const p = challenge.params;
  const device = p.devices[0] ?? 'your phone';
  const wait = useCountdown(p.resendAllowedAt);
  return (
    <div data-kc-part="form" data-kc-challenge="push" data-kc-status={p.status ?? (p.sent ? 'pending' : 'idle')}>
      <Description>{p.sent ? strings.pushSent(device) : strings.pushCanSend(device)}</Description>
      {p.isPending && p.userVerificationNumber && (
        <p data-kc-part="number" aria-live="polite">
          {strings.pushChooseNumber(p.userVerificationNumber)}
        </p>
      )}
      {p.isPending && (
        <p data-kc-part="status" aria-live="polite">
          {strings.pushWaiting}
        </p>
      )}
      {challenge.error && (
        <p data-kc-part="error" role="alert">
          {challengeError(strings, challenge)}
        </p>
      )}
      <button data-kc-part={p.isPending ? 'secondary' : 'submit'} type="button" disabled={isSubmitting || wait > 0} onClick={() => void submit({ kind: 'pushResend' })}>
        {wait > 0 ? strings.resendCodeIn(wait) : strings.sendRequest}
      </button>
    </div>
  );
}

export function RecoveryCodeChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'recovery_code'>) {
  const [code, setCode] = useState('');
  const remaining = challenge.params.remaining;
  return (
    <Form type="recovery_code" onSubmit={() => submit({ kind: 'recoveryCode', code: code.trim() })}>
      {remaining !== undefined && <Description>{strings.recoveryCodeLeft(remaining)}</Description>}
      <Field
        label={challenge.label ?? strings.recoveryCode}
        name="recovery_code"
        value={code}
        onChange={setCode}
        autoComplete="one-time-code"
        autoFocus
        disabled={isSubmitting}
        error={challengeError(strings, challenge)}
      />
      <Submit label={strings.verify} disabled={isSubmitting || code.trim().length === 0} />
    </Form>
  );
}

export function UpdatePasswordChallenge({ challenge, context, strings, isSubmitting, submit }: ChallengeProps<'update_password'>) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const offerLogout = challenge.params.logoutOtherSessions !== undefined;
  const [logoutOthers, setLogoutOthers] = useState(challenge.params.logoutOtherSessions ?? false);
  const mismatch = confirm.length > 0 && confirm !== password;
  return (
    <Form
      type="update_password"
      onSubmit={() =>
        submit({ kind: 'updatePassword', password, confirm, ...(offerLogout ? { logoutOtherSessions: logoutOthers } : {}) })
      }
    >
      <Description>{challenge.label ?? strings.chooseNewPassword}</Description>
      <input type="text" name="username" autoComplete="username" value={challenge.params.username ?? context.username ?? ''} readOnly hidden />
      {challenge.params.hints.length > 0 && (
        <ul data-kc-part="hints">
          {challenge.params.hints.map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
      )}
      <Field label={strings.newPassword} name="password" type="password" value={password} onChange={setPassword} autoComplete="new-password" autoFocus disabled={isSubmitting} error={challengeError(strings, challenge)} />
      <Field
        label={strings.confirmNewPassword}
        name="password_confirm"
        type="password"
        value={confirm}
        onChange={setConfirm}
        autoComplete="new-password"
        disabled={isSubmitting}
        error={mismatch ? strings.passwordsDoNotMatch : undefined}
      />
      {offerLogout && (
        <label data-kc-part="checkbox">
          <input type="checkbox" checked={logoutOthers} onChange={(e) => setLogoutOthers(e.target.checked)} disabled={isSubmitting} />
          {strings.logoutOtherSessions}
        </label>
      )}
      <Submit label={strings.updatePassword} disabled={isSubmitting || password.length === 0 || mismatch || confirm.length === 0} />
      {challenge.skippable && <Secondary label={strings.cancel} onClick={() => void submit({ kind: 'skip' })} disabled={isSubmitting} />}
    </Form>
  );
}

export function VerifyEmailChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'verify_email'>) {
  const [code, setCode] = useState('');
  const p = challenge.params;
  const wait = useCountdown(p.resendAllowedAt);
  return (
    <Form type="verify_email" onSubmit={() => (p.sent ? submit({ kind: 'verifyEmail', code }) : submit({ kind: 'verifyEmailResend' }))}>
      <Description>{p.sent ? strings.weSentEmailCode(p.digits, p.emailMasked ?? '') : strings.verifyEmail}</Description>
      {p.sent && (
        <Field label={strings.code} name="code" value={code} onChange={setCode} {...codeLength(p.digits)} autoFocus disabled={isSubmitting} error={challengeError(strings, challenge)} />
      )}
      {p.sent ? <Submit label={strings.verify} disabled={isSubmitting || code.length === 0} /> : <Submit label={strings.sendCode} disabled={isSubmitting || wait > 0} />}
      {p.sent && (
        <Secondary label={wait > 0 ? strings.resendCodeIn(wait) : strings.resendCode} onClick={() => void submit({ kind: 'verifyEmailResend' })} disabled={isSubmitting || wait > 0} />
      )}
      {challenge.skippable && <Secondary label={strings.notNow} onClick={() => void submit({ kind: 'skip' })} disabled={isSubmitting} />}
    </Form>
  );
}

export function TermsChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'terms'>) {
  const p = challenge.params;
  return (
    <div data-kc-part="form" data-kc-challenge="terms">
      <Description>{challenge.label ?? strings.terms}</Description>
      {p.text && <div data-kc-part="terms-text">{p.text}</div>}
      {p.url && (
        <a data-kc-part="link" href={p.url} target="_blank" rel="noreferrer">
          {strings.readFullTerms}
        </a>
      )}
      <button data-kc-part="submit" type="button" disabled={isSubmitting} onClick={() => void submit({ kind: 'terms', accepted: true })}>
        {strings.accept}
      </button>
      <button data-kc-part="secondary" type="button" disabled={isSubmitting} onClick={() => void submit({ kind: 'terms', accepted: false })}>
        {strings.decline}
      </button>
    </div>
  );
}

export function PinChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'pin'>) {
  const [pin, setPin] = useState('');
  const locked = isChallengeLocked(challenge);
  return (
    <Form type="pin" onSubmit={() => submit({ kind: 'pin', pin })}>
      <Description>{strings.pinSubtitle(challenge.params.length)}</Description>
      <Field
        label={challenge.label ?? strings.pinTitle}
        name="pin"
        type="password"
        value={pin}
        onChange={setPin}
        inputMode="numeric"
        maxLength={challenge.params.length}
        autoComplete="off"
        autoFocus
        disabled={isSubmitting || locked}
        error={challengeError(strings, challenge)}
      />
      <Submit label={strings.continue} disabled={isSubmitting || locked || pin.length !== challenge.params.length} />
    </Form>
  );
}

export function PinSetupChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps<'pin_setup'>) {
  const [pin, setPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const length = challenge.params.length;
  return (
    <Form type="pin_setup" onSubmit={() => submit({ kind: 'pinSetup', pin, confirm })}>
      <Description>{strings.pinChooseSubtitle(length)}</Description>
      <Field label={strings.pinChooseTitle} name="pin" type="password" value={pin} onChange={setPin} inputMode="numeric" maxLength={length} autoComplete="off" autoFocus disabled={isSubmitting} error={challengeError(strings, challenge)} />
      <Field label={strings.pinConfirm} name="pin_confirm" type="password" value={confirm} onChange={setConfirm} inputMode="numeric" maxLength={length} autoComplete="off" disabled={isSubmitting} />
      <Submit label={strings.continue} disabled={isSubmitting || pin.length !== length || confirm.length !== length} />
      {challenge.skippable && <Secondary label={strings.notNow} onClick={() => void submit({ kind: 'skip' })} disabled={isSubmitting} />}
    </Form>
  );
}

/** Challenge types the web cannot answer in place (push enrollment is for phones, `select`, unknown). */
export function UnsupportedChallenge({ challenge, strings, isSubmitting, submit }: ChallengeProps) {
  return (
    <div data-kc-part="form" data-kc-challenge={challenge.wireType}>
      <Description>{strings.unsupported(challenge.wireType)}</Description>
      {challenge.skippable && <Secondary label={strings.notNow} onClick={() => void submit({ kind: 'skip' })} disabled={isSubmitting} />}
    </div>
  );
}

export const defaultChallengeComponents: ChallengeComponents = {
  username: UsernameChallenge,
  password: PasswordChallenge,
  totp: TotpChallenge,
  otp: OtpChallenge,
  passkey: PasskeyChallenge,
  passkey_registration: PasskeyRegistrationChallenge,
  push: PushChallenge,
  push_enrollment: UnsupportedChallenge as ComponentType<ChallengeProps<'push_enrollment'>>,
  recovery_code: RecoveryCodeChallenge,
  update_password: UpdatePasswordChallenge,
  verify_email: VerifyEmailChallenge,
  terms: TermsChallenge,
  pin: PinChallenge,
  pin_setup: PinSetupChallenge,
  select: UnsupportedChallenge as ComponentType<ChallengeProps<'select'>>,
  unknown: UnsupportedChallenge as ComponentType<ChallengeProps<'unknown'>>,
};
