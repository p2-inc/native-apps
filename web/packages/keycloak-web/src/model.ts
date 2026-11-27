/**
 * The challenge model (spec/03 §3–§4): a discriminated union on `type` with typed `params`, the twin
 * of `ChallengeModels.swift` / `ChallengeModels.kt` and of the React Native module's `model.ts`.
 * Unknown fields are ignored and kept in `raw` (spec/03 §10); unknown types decode as
 * `type: 'unknown'` with the wire value in `wireType`, so the app can offer another way in or the
 * browser (spec/03 §4.11).
 */

import {
  arr,
  asObject,
  bool,
  epochMillis,
  int,
  str,
  strings,
  type JsonObject,
  type JsonValue,
} from './json';

/** Milliseconds until `instant`, zero when it has passed or is absent (`resendWait()` of the SDKs). */
export function millisUntil(
  instant: number | undefined,
  now: number = Date.now()
): number {
  return instant === undefined || instant <= now ? 0 : instant - now;
}

// MARK: - Challenge types

/** The challenge types of spec/03 §4 by wire value. */
export const ChallengeTypes = [
  'username',
  'password',
  'passkey',
  'passkey_registration',
  'totp',
  'otp',
  'push',
  'recovery_code',
  'select',
  'update_password',
  'verify_email',
  'terms',
  'push_enrollment',
  // PIN extension (spec/03 §4.17, §4.18); servers advertise them only when it is installed.
  'pin',
  'pin_setup',
] as const;
export type KnownChallengeType = (typeof ChallengeTypes)[number];

/** Native required actions served in-band (spec/03 §4.11): always the single entry of their set. */
const REQUIRED_ACTIONS: ReadonlySet<string> = new Set([
  'passkey_registration',
  'update_password',
  'verify_email',
  'terms',
  'push_enrollment',
  'pin_setup',
]);

/** `error` of a descriptor: the previous attempt at this challenge failed (spec/03 §3.3). */
export interface ChallengeError {
  code: string;
  message?: string;
}

export const ChallengeErrorCode = {
  invalidCredential: 'invalid_credential',
  invalidUser: 'invalid_user',
  missingCredential: 'missing_credential',
  invalidAttestation: 'invalid_attestation',
  /** `otp`: the code expired or was used up; `otpResend` is needed (spec/03 §4.6). */
  expiredCode: 'expired_code',
  /** `otp`: `otpResend` before `resend_allowed_at`; not a failure. */
  resendTooSoon: 'resend_too_soon',
  passwordMismatch: 'password_mismatch',
  invalidPassword: 'invalid_password',
  /** `push`: the device user refused the sign-in (spec/03 §4.7). */
  denied: 'denied',
  /** `push`: the pending approval expired unanswered. */
  expired: 'expired',
  /**
   * `pin`: the PIN reached its attempt limit and must be reset (on the web or by an administrator);
   * every further attempt fails, `retry.remaining` is 0 (spec/03 §4.17).
   */
  credentialLocked: 'credential_locked',
  /** `pin_setup`: `pin_confirm` differed (spec/03 §4.18). */
  pinMismatch: 'pin_mismatch',
  /** `pin_setup`: not exactly `length` digits. */
  invalidFormat: 'invalid_format',
  /** `pin_setup`: rejected as easy to guess (all the same digit, a simple run). */
  weakPin: 'weak_pin',
} as const;

// MARK: - Typed params (spec/03 §4.1–§4.15)

export interface UsernameParams {
  allowEmail: boolean;
  hint?: string;
}

export interface PasswordParams {
  usernameKnown: boolean;
}

export interface TotpParams {
  digits: number;
  period: number;
  algorithm?: string;
  credentialLabels: string[];
  /** The user's authenticator apps; answer with `credentialId` to pick one. */
  credentials: { id: string; label: string }[];
}

export interface OtpParams {
  /** `email` | `sms` */
  channel: string;
  /** `a***@example.com`; never the full address. */
  destinationMasked?: string;
  digits: number;
  /** Code lifetime in seconds from sending. */
  ttl?: number;
  /** `true` when a code is outstanding; `false` when the server waits for `otpResend`. */
  sent: boolean;
  /** Earliest time (epoch milliseconds) another `otpResend` is accepted. */
  resendAllowedAt?: number;
}

export interface RecoveryCodeParams {
  remaining?: number;
  warningThreshold?: number;
  /** Suggest generating new codes (remaining at or below the realm's threshold). */
  shouldWarn: boolean;
}

export interface UpdatePasswordParams {
  username?: string;
  /**
   * The suggested default for "Sign out of other devices" when the server offers it (spec/21 D5);
   * `undefined` when it does not (older servers): then don't show the option or send the field.
   */
  logoutOtherSessions?: boolean;
  /** Keycloak policy id → configured value (`length: 8`, `digits: 1`, `notUsername: true`, …). */
  policy: JsonObject;
  minimumLength?: number;
  maximumLength?: number;
  /** Human-readable hints in a stable order (English), as the native SDKs build them. */
  hints: string[];
}

export interface VerifyEmailParams {
  emailMasked?: string;
  digits: number;
  ttl?: number;
  sent: boolean;
  resendAllowedAt?: number;
}

export interface TermsParams {
  text?: string;
  url?: string;
  version?: string;
}

export interface PushParams {
  sent: boolean;
  /** The push MFA challenge id the device sees in `/login/pending`. */
  cid?: string;
  expiresAt?: number;
  /** Seconds between `pushPoll` answers. */
  pollInterval: number;
  status?: 'pending' | 'approved' | 'denied' | 'expired';
  /** Number match: the number this client shows; the user picks it on the device. */
  userVerificationNumber?: string;
  /** Labels of the user's enrolled devices. */
  devices: string[];
  resendAllowedAt?: number;
  /** `true` while a poll is worthwhile. */
  isPending: boolean;
}

export interface PushEnrollmentParams {
  enrollmentToken?: string;
  expiresIn?: number;
  deviceApiBase?: string;
  userId?: string;
}

/** spec/03 §4.17: the PIN factor. */
export interface PinParams {
  /** The length of the user's stored PIN: show that many slots and a numeric keypad. */
  length: number;
}

/** spec/03 §4.18: set a PIN (required action). */
export interface PinSetupParams {
  /** The PIN length the realm asks for. */
  length: number;
}

export interface PasskeyAssertionParams {
  challenge: string;
  rpId: string;
  timeoutMilliseconds?: number;
  userVerification: string;
  allowCredentials: { id: string; type: string; transports: string[] }[];
  /** `true` when `allow_credentials` is empty: username-less login. */
  discoverable: boolean;
}

export interface PasskeyRegistrationParams {
  challenge: string;
  rp: { id: string; name?: string };
  user: { id: string; name: string; displayName?: string };
  pubKeyCredParams: number[];
  residentKey?: string;
  requireResidentKey: boolean;
  userVerification: string;
  authenticatorAttachment?: string;
  attestation: string;
  excludeCredentials: string[];
  timeoutMilliseconds?: number;
}

interface ChallengeBase {
  /** `challenge_id`: the execution id, or the required action's provider id. */
  id: string;
  /** The type as sent on the wire (also for `unknown`). */
  wireType: string;
  label?: string;
  required: boolean;
  error?: ChallengeError;
  retry?: { remaining?: number };
  /** The user may decline this required action for this login with a `skip` answer. */
  skippable: boolean;
  /** Whether this version of the module can answer the type (not `select`, not `unknown`). */
  supported: boolean;
  /** A native required action (spec/03 §4.11). */
  requiredAction: boolean;
  /** The `params` object as received (an empty object when absent). */
  rawParams: JsonObject;
  /** The whole descriptor as received. */
  raw: JsonObject;
}

type Typed<T extends string, P> = ChallengeBase & { type: T; params: P };

/** A challenge descriptor (spec/03 §3.3), narrowed by `type`. */
export type Challenge =
  | Typed<'username', UsernameParams>
  | Typed<'password', PasswordParams>
  | Typed<'totp', TotpParams>
  | Typed<'otp', OtpParams>
  | Typed<'recovery_code', RecoveryCodeParams>
  | Typed<'passkey', PasskeyAssertionParams | undefined>
  | Typed<'passkey_registration', PasskeyRegistrationParams | undefined>
  | Typed<'push', PushParams>
  | Typed<'push_enrollment', PushEnrollmentParams>
  | Typed<'update_password', UpdatePasswordParams>
  | Typed<'verify_email', VerifyEmailParams>
  | Typed<'terms', TermsParams>
  | Typed<'pin', PinParams>
  | Typed<'pin_setup', PinSetupParams>
  | Typed<'select', JsonObject>
  | Typed<'unknown', JsonObject>;

export type ChallengeType = Challenge['type'];

/**
 * `pin` with `credential_locked` (spec/03 §4.17): the PIN cannot be used until it is reset; another
 * attempt always fails, so offer cancel (or another alternative) instead.
 */
export function isChallengeLocked(challenge: Challenge): boolean {
  return challenge.error?.code === ChallengeErrorCode.credentialLocked;
}

/**
 * Whether `pin` has the shape a `pin_setup` server accepts (exactly `length` ASCII digits); the
 * server always validates (and also rejects weak PINs).
 */
export function isWellFormedPin(params: PinSetupParams, pin: string): boolean {
  return pin.length === params.length && /^[0-9]*$/.test(pin);
}

/** The challenge narrowed to one type. */
export type ChallengeOf<T extends ChallengeType> = Extract<
  Challenge,
  { type: T }
>;

function passwordHints(policy: JsonObject): string[] {
  const hints: string[] = [];
  const plural = (n: number, word: string) =>
    `At least ${n} ${word}${n === 1 ? '' : 's'}`;
  const length = int(policy.length);
  if (length !== undefined) hints.push(`At least ${length} characters`);
  const maxLength = int(policy.maxLength);
  if (maxLength !== undefined) hints.push(`At most ${maxLength} characters`);
  const digits = int(policy.digits);
  if (digits !== undefined) hints.push(plural(digits, 'digit'));
  const upper = int(policy.upperCase);
  if (upper !== undefined) hints.push(plural(upper, 'upper-case letter'));
  const lower = int(policy.lowerCase);
  if (lower !== undefined) hints.push(plural(lower, 'lower-case letter'));
  const special = int(policy.specialChars);
  if (special !== undefined) hints.push(plural(special, 'special character'));
  if (policy.notUsername !== undefined) hints.push('Not your username');
  if (policy.notEmail !== undefined) hints.push('Not your email address');
  if (policy.notContainsUsername !== undefined)
    hints.push('Must not contain your username');
  const history = int(policy.passwordHistory);
  if (history !== undefined)
    hints.push(`Not one of your last ${history} passwords`);
  const regex = str(policy.regexPattern);
  if (regex !== undefined) hints.push(`Must match ${regex}`);
  return hints;
}

function parsePasskeyAssertion(
  p: JsonObject
): PasskeyAssertionParams | undefined {
  const challenge = str(p.challenge);
  const rpId = str(p.rp_id);
  if (challenge === undefined || rpId === undefined) return undefined;
  const allowCredentials = arr(p.allow_credentials).flatMap((entry) => {
    const o = asObject(entry);
    const id = str(o?.id);
    return id === undefined
      ? []
      : [
          {
            id,
            type: str(o?.type) ?? 'public-key',
            transports: strings(o?.transports),
          },
        ];
  });
  return {
    challenge,
    rpId,
    timeoutMilliseconds: int(p.timeout),
    userVerification: str(p.user_verification) ?? 'preferred',
    allowCredentials,
    discoverable: bool(p.discoverable) ?? allowCredentials.length === 0,
  };
}

function parsePasskeyRegistration(
  p: JsonObject
): PasskeyRegistrationParams | undefined {
  const challenge = str(p.challenge);
  const rp = asObject(p.rp);
  const user = asObject(p.user);
  const rpId = str(rp?.id);
  const userId = str(user?.id);
  const userName = str(user?.name);
  if (
    challenge === undefined ||
    rpId === undefined ||
    userId === undefined ||
    userName === undefined
  ) {
    return undefined;
  }
  const selection = asObject(p.authenticator_selection);
  return {
    challenge,
    rp: { id: rpId, name: str(rp?.name) },
    user: { id: userId, name: userName, displayName: str(user?.display_name) },
    pubKeyCredParams: arr(p.pub_key_cred_params).flatMap((e) => {
      const alg = int(asObject(e)?.alg);
      return alg === undefined ? [] : [alg];
    }),
    residentKey: str(selection?.resident_key),
    requireResidentKey: bool(selection?.require_resident_key) ?? false,
    userVerification: str(selection?.user_verification) ?? 'preferred',
    authenticatorAttachment: str(selection?.authenticator_attachment),
    attestation: str(p.attestation) ?? 'none',
    excludeCredentials: arr(p.exclude_credentials).flatMap((e) => {
      const id = str(asObject(e)?.id);
      return id === undefined ? [] : [id];
    }),
    timeoutMilliseconds: int(p.timeout),
  };
}

function parsePush(p: JsonObject): PushParams {
  const sent = bool(p.sent) ?? false;
  const statusWire = str(p.status);
  const status =
    statusWire === 'pending' ||
    statusWire === 'approved' ||
    statusWire === 'denied' ||
    statusWire === 'expired'
      ? statusWire
      : undefined;
  const verification = asObject(p.user_verification);
  return {
    sent,
    cid: str(p.cid),
    expiresAt: epochMillis(p.expires_at),
    pollInterval: Math.max(1, int(p.poll_interval) ?? 3),
    status,
    userVerificationNumber:
      str(verification?.type) === 'number_match'
        ? str(verification?.number)
        : undefined,
    devices: arr(p.devices).flatMap((d) => {
      const label = str(asObject(d)?.label);
      return label === undefined ? [] : [label];
    }),
    resendAllowedAt: epochMillis(p.resend_allowed_at),
    isPending: sent && (status === undefined || status === 'pending'),
  };
}

/** The typed params of a wire type (`undefined` for passkey params missing a required field). */
function typedParams(type: string, p: JsonObject): unknown {
  switch (type) {
    case 'username':
      return {
        allowEmail: bool(p.allow_email) ?? false,
        hint: str(p.hint),
      } satisfies UsernameParams;
    case 'password':
      return {
        usernameKnown: bool(p.username_known) ?? true,
      } satisfies PasswordParams;
    case 'totp':
      return {
        digits: int(p.digits) ?? 6,
        period: int(p.period) ?? 30,
        algorithm: str(p.algorithm),
        credentialLabels: strings(p.credential_labels),
        credentials: arr(p.credentials).flatMap((entry) => {
          const o = asObject(entry);
          const id = str(o?.id);
          return id === undefined ? [] : [{ id, label: str(o?.label) ?? '' }];
        }),
      } satisfies TotpParams;
    case 'otp':
      return {
        channel: str(p.channel) ?? 'email',
        destinationMasked: str(p.destination_masked),
        digits: int(p.digits) ?? 6,
        ttl: int(p.ttl),
        sent: bool(p.sent) ?? false,
        resendAllowedAt: epochMillis(p.resend_allowed_at),
      } satisfies OtpParams;
    case 'recovery_code': {
      const remaining = int(p.remaining);
      const warningThreshold = int(p.warning_threshold);
      return {
        remaining,
        warningThreshold,
        shouldWarn:
          remaining !== undefined &&
          warningThreshold !== undefined &&
          remaining <= warningThreshold,
      } satisfies RecoveryCodeParams;
    }
    case 'update_password': {
      const policy = asObject(p.policy) ?? {};
      return {
        username: str(p.username),
        logoutOtherSessions: bool(p.logout_other_sessions),
        policy,
        minimumLength: int(policy.length),
        maximumLength: int(policy.maxLength),
        hints: passwordHints(policy),
      } satisfies UpdatePasswordParams;
    }
    case 'verify_email':
      return {
        emailMasked: str(p.email_masked),
        digits: int(p.digits) ?? 6,
        ttl: int(p.ttl),
        sent: bool(p.sent) ?? false,
        resendAllowedAt: epochMillis(p.resend_allowed_at),
      } satisfies VerifyEmailParams;
    case 'terms':
      return {
        text: str(p.text),
        url: str(p.url),
        version: str(p.version),
      } satisfies TermsParams;
    case 'push':
      return parsePush(p);
    case 'push_enrollment':
      return {
        enrollmentToken: str(p.enrollment_token),
        expiresIn: int(p.expires_in),
        deviceApiBase: str(p.device_api_base),
        userId: str(p.user_id),
      } satisfies PushEnrollmentParams;
    case 'pin':
      return { length: int(p.length) ?? 4 } satisfies PinParams;
    case 'pin_setup':
      return { length: int(p.length) ?? 4 } satisfies PinSetupParams;
    case 'passkey':
      return parsePasskeyAssertion(p);
    case 'passkey_registration':
      return parsePasskeyRegistration(p);
    default:
      return p;
  }
}

/** Parses one descriptor; `undefined` when `type` or `id` is missing (as the native SDKs do). */
export function parseChallenge(json: JsonValue): Challenge | undefined {
  const o = asObject(json);
  const wireType = str(o?.type);
  const id = str(o?.id);
  if (o === undefined || wireType === undefined || id === undefined)
    return undefined;
  const known = (ChallengeTypes as readonly string[]).includes(wireType);
  const type = known ? wireType : 'unknown';
  const rawParams = asObject(o.params) ?? {};
  const error = asObject(o.error);
  const errorCode = str(error?.code);
  const retry = asObject(o.retry);
  const challenge = {
    id,
    type,
    wireType,
    label: str(o.label),
    required: bool(o.required) ?? true,
    error:
      errorCode === undefined
        ? undefined
        : { code: errorCode, message: str(error?.message) },
    retry:
      retry === undefined ? undefined : { remaining: int(retry.remaining) },
    skippable: bool(o.skippable) ?? false,
    supported: known && wireType !== 'select',
    requiredAction: REQUIRED_ACTIONS.has(wireType),
    params: typedParams(type, rawParams),
    rawParams,
    raw: o,
  };
  return challenge as Challenge;
}

// MARK: - Flow context and steps

/** Informational `context` of a challenge response (spec/03 §3.2). */
export interface FlowContext {
  username?: string;
  displayName?: string;
  clientName?: string;
  acrRequested?: string;
  stepUp: boolean;
  raw: JsonObject;
}

export function parseFlowContext(json: JsonValue | undefined): FlowContext {
  const o = asObject(json) ?? {};
  return {
    username: str(o.username),
    displayName: str(o.display_name),
    clientName: str(o.client_name),
    acrRequested: str(o.acr_requested),
    stepUp: bool(o.step_up) ?? false,
    raw: o,
  };
}

/** A `redirect_to_web` answer (spec/03 §3.4). */
export interface RedirectToWebRequest {
  /** PAR `request_uri` (single use). */
  requestUri: string;
  expiresIn?: number;
  redirectUri: string;
  state?: string;
  /** Informational, e.g. `required_action:UPDATE_PASSWORD`. */
  reason?: string;
  errorDescription?: string;
  raw: JsonObject;
}

export function parseRedirectToWeb(
  json: JsonValue | undefined
): RedirectToWebRequest | undefined {
  const o = asObject(json);
  const requestUri = str(o?.request_uri);
  const redirectUri = str(o?.redirect_uri);
  if (o === undefined || requestUri === undefined || redirectUri === undefined)
    return undefined;
  return {
    requestUri,
    expiresIn: int(o.expires_in),
    redirectUri,
    state: str(o.state),
    reason: str(o.reason),
    errorDescription: str(o.error_description),
    raw: o,
  };
}

/**
 * Outcome of an application-initiated action (spec/21): `success`, `cancelled` (the user declined),
 * `error` (unknown, disabled, or not allowed to be started by the app), or a newer value.
 */
export type KcActionStatus = 'success' | 'cancelled' | 'error' | (string & {});

// MARK: - Answers

/** The §4.3 wire fields of a WebAuthn assertion, all base64url without padding. */
export interface PasskeyAssertion {
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
  /** Present for resident credentials; names the user in discoverable logins. */
  userHandle?: string;
}

/** The §4.4 / §6 wire fields of a WebAuthn registration (attestation), base64url without padding. */
export interface PasskeyAttestation {
  credentialId: string;
  clientDataJson: string;
  attestationObject: string;
  /** e.g. `["internal", "hybrid"]`. */
  transports: string[];
}

/**
 * The client's answer to one challenge (spec/03 §4), named like the native `ChallengeAnswer` cases.
 * Ceremonies have helpers that build the answer: `flow.usePasskey` and `flow.registerPasskey`.
 */
export type ChallengeAnswer =
  | { kind: 'username'; username: string }
  | { kind: 'password'; password: string }
  | { kind: 'totp'; code: string; credentialId?: string }
  | { kind: 'passkey'; assertion: PasskeyAssertion }
  | {
      kind: 'passkeyRegistration';
      attestation: PasskeyAttestation;
      label?: string;
    }
  | { kind: 'otp'; code: string }
  | { kind: 'otpResend' }
  | { kind: 'recoveryCode'; code: string }
  | {
      kind: 'updatePassword';
      password: string;
      confirm: string;
      /** "Sign out of other devices" (spec/21 D5); sent only when set. */
      logoutOtherSessions?: boolean;
    }
  | { kind: 'verifyEmail'; code: string }
  | { kind: 'verifyEmailResend' }
  | { kind: 'terms'; accepted: boolean }
  | { kind: 'pushResend' }
  | { kind: 'pushPoll' }
  | { kind: 'pushEnrollment'; token: string }
  | { kind: 'pushEnrollmentCheck' }
  /** `pin` (spec/03 §4.17): the user's PIN, sent as `pin`. */
  | { kind: 'pin'; pin: string }
  /** `pin_setup` (spec/03 §4.18): the new PIN, sent as `pin` + `pin_confirm`. */
  | { kind: 'pinSetup'; pin: string; confirm: string }
  /** Declines a skippable required action for this login ("Not now"). */
  | { kind: 'skip' }
  /** Any other answer, e.g. for an extension challenge type (spec/03 §4.16). */
  | { kind: 'custom'; fields: [string, string][] };

/** The challenge types an answer kind can be sent for (`skip` and `custom`: any). */
export const answerChallengeType: Record<
  Exclude<ChallengeAnswer['kind'], 'skip' | 'custom'>,
  KnownChallengeType
> = {
  username: 'username',
  password: 'password',
  totp: 'totp',
  passkey: 'passkey',
  passkeyRegistration: 'passkey_registration',
  otp: 'otp',
  otpResend: 'otp',
  recoveryCode: 'recovery_code',
  updatePassword: 'update_password',
  verifyEmail: 'verify_email',
  verifyEmailResend: 'verify_email',
  terms: 'terms',
  pushResend: 'push',
  pushPoll: 'push',
  pushEnrollment: 'push_enrollment',
  pushEnrollmentCheck: 'push_enrollment',
  pin: 'pin',
  pinSetup: 'pin_setup',
};

export function passkeyAssertionFields(a: PasskeyAssertion): [string, string][] {
  const fields: [string, string][] = [
    ['credential_id', a.credentialId],
    ['client_data_json', a.clientDataJson],
    ['authenticator_data', a.authenticatorData],
    ['signature', a.signature],
  ];
  if (a.userHandle !== undefined) fields.push(['user_handle', a.userHandle]);
  return fields;
}

export function passkeyAttestationFields(
  a: PasskeyAttestation
): [string, string][] {
  return [
    ['credential_id', a.credentialId],
    ['client_data_json', a.clientDataJson],
    ['attestation_object', a.attestationObject],
    ['transports', a.transports.join(',')],
  ];
}

/** Type-specific form fields of an answer (without `auth_session`, `challenge_type`, `challenge_id`). */
export function answerFields(answer: ChallengeAnswer): [string, string][] {
  switch (answer.kind) {
    case 'username':
      return [['username', answer.username]];
    case 'password':
      return [['password', answer.password]];
    case 'totp':
      return answer.credentialId
        ? [
            ['totp', answer.code],
            ['credential_id', answer.credentialId],
          ]
        : [['totp', answer.code]];
    case 'passkey':
      return passkeyAssertionFields(answer.assertion);
    case 'passkeyRegistration':
      return answer.label
        ? [...passkeyAttestationFields(answer.attestation), ['label', answer.label]]
        : passkeyAttestationFields(answer.attestation);
    case 'otp':
      return [['otp', answer.code]];
    case 'otpResend':
    case 'verifyEmailResend':
    case 'pushResend':
      return [['action', 'resend']];
    case 'recoveryCode':
      return [['recovery_code', answer.code]];
    case 'updatePassword': {
      const fields: [string, string][] = [
        ['password', answer.password],
        ['password_confirm', answer.confirm],
      ];
      if (answer.logoutOtherSessions !== undefined)
        fields.push(['logout_other_sessions', String(answer.logoutOtherSessions)]);
      return fields;
    }
    case 'verifyEmail':
      return [['code', answer.code]];
    case 'terms':
      return [['accepted', String(answer.accepted)]];
    case 'pushPoll':
      return [['action', 'poll']];
    case 'pushEnrollment':
      return [['token', answer.token]];
    case 'pushEnrollmentCheck':
      return [['action', 'check']];
    case 'pin':
      return [['pin', answer.pin]];
    case 'pinSetup':
      return [
        ['pin', answer.pin],
        ['pin_confirm', answer.confirm],
      ];
    case 'skip':
      return [['action', 'skip']];
    case 'custom':
      return answer.fields;
  }
}
