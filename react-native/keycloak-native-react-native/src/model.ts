/**
 * The challenge model (spec/03 §3–§4) in TypeScript: a discriminated union on `type` with typed
 * `params`, the twin of `ChallengeModels.swift` / `ChallengeModels.kt`. The native side forwards the
 * descriptors as the server sent them; these functions build the typed views. Unknown fields are
 * ignored and kept in `raw` (spec/03 §10); unknown types decode as `type: 'unknown'` with the wire
 * value in `wireType`, so the app can offer another way in or the browser (spec/03 §4.11).
 */

export type JsonValue =
  null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

// MARK: - JSON helpers

function asObject(value: JsonValue | undefined): JsonObject | undefined {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    value !== undefined
    ? value
    : undefined;
}

function str(value: JsonValue | undefined): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function bool(value: JsonValue | undefined): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function num(value: JsonValue | undefined): number | undefined {
  return typeof value === 'number' && Number.isFinite(value)
    ? value
    : undefined;
}

/** Integers only, like the native SDKs' `intValue`. */
function int(value: JsonValue | undefined): number | undefined {
  const n = num(value);
  return n !== undefined && Number.isInteger(n) ? n : undefined;
}

function arr(value: JsonValue | undefined): JsonValue[] {
  return Array.isArray(value) ? value : [];
}

function strings(value: JsonValue | undefined): string[] {
  return arr(value).filter((v): v is string => typeof v === 'string');
}

/** The protocol sends instants as seconds since the epoch; the model uses milliseconds. */
function epochMillis(value: JsonValue | undefined): number | undefined {
  const n = num(value);
  return n === undefined ? undefined : Math.round(n * 1000);
}

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
 * The tokens the native side hands to JavaScript. The refresh token and the post-login
 * `auth_session` stay native: `KeycloakNative.credentials()` refreshes, and `stepUp` reads the session.
 */
export interface Credentials {
  accessToken: string;
  /** `Bearer` or `DPoP`. */
  tokenType: string;
  idToken?: string;
  scope?: string;
  /** Epoch milliseconds. */
  expiresAt: number;
  refreshExpiresAt?: number;
  issuedAt: number;
  hasRefreshToken: boolean;
  isDPoPBound: boolean;
}

export function parseCredentials(json: JsonValue | undefined): Credentials {
  const o = asObject(json) ?? {};
  const accessToken = str(o.accessToken);
  const expiresAt = num(o.expiresAt);
  if (accessToken === undefined || expiresAt === undefined) {
    throw new NativeAuthError(
      NativeAuthErrorCode.invalidResponse,
      'The native module returned credentials without an access token'
    );
  }
  const tokenType = str(o.tokenType) ?? 'Bearer';
  return {
    accessToken,
    tokenType,
    idToken: str(o.idToken),
    scope: str(o.scope),
    expiresAt,
    refreshExpiresAt: num(o.refreshExpiresAt),
    issuedAt: num(o.issuedAt) ?? Date.now(),
    hasRefreshToken: bool(o.hasRefreshToken) ?? false,
    isDPoPBound: bool(o.isDPoPBound) ?? tokenType.toLowerCase() === 'dpop',
  };
}

/** What `start()` / `respond()` hand back (spec/05 §2.1). */
export type FlowStep =
  | {
      kind: 'challenges';
      /** The challenge set in server order. */
      challenges: Challenge[];
      /** The entries this module can answer, in server order. */
      supportedChallenges: Challenge[];
      context: FlowContext;
      /** Remaining lifetime of the authentication session, in seconds. */
      expiresIn?: number;
    }
  | { kind: 'authorized'; credentials: Credentials }
  | { kind: 'redirectToWeb'; request: RedirectToWebRequest };

/** Parses the native module's step JSON (`NativeFlowStep`, spec/19 §4). */
export function parseFlowStep(json: JsonValue): FlowStep {
  const o = asObject(json);
  switch (str(o?.kind)) {
    case 'challenges': {
      const challenges = arr(o?.challenges).flatMap((c) => {
        const parsed = parseChallenge(c);
        return parsed === undefined ? [] : [parsed];
      });
      return {
        kind: 'challenges',
        challenges,
        supportedChallenges: challenges.filter((c) => c.supported),
        context: parseFlowContext(o?.context),
        expiresIn: int(o?.expiresIn),
      };
    }
    case 'authorized':
      return {
        kind: 'authorized',
        credentials: parseCredentials(o?.credentials),
      };
    case 'redirectToWeb': {
      const request = parseRedirectToWeb(o?.request);
      if (request !== undefined) return { kind: 'redirectToWeb', request };
      break;
    }
  }
  throw new NativeAuthError(
    NativeAuthErrorCode.invalidResponse,
    'The native module returned an unknown flow step'
  );
}

// MARK: - Answers

/**
 * The client's answer to one challenge (spec/03 §4), named like the native `ChallengeAnswer` cases.
 * The native side turns it into the form fields. Ceremonies run natively in one call instead:
 * `flow.usePasskey`, `flow.registerPasskey` and `flow.enrollPush` (spec/19 §3).
 */
export type ChallengeAnswer =
  | { kind: 'username'; username: string }
  | { kind: 'password'; password: string }
  | { kind: 'totp'; code: string; credentialId?: string }
  | { kind: 'otp'; code: string }
  | { kind: 'otpResend' }
  | { kind: 'recoveryCode'; code: string }
  | { kind: 'updatePassword'; password: string; confirm: string }
  | { kind: 'verifyEmail'; code: string }
  | { kind: 'verifyEmailResend' }
  | { kind: 'terms'; accepted: boolean }
  | { kind: 'pushResend' }
  | { kind: 'pushPoll' }
  | { kind: 'pushEnrollmentCheck' }
  /** `pin` (spec/03 §4.17): the user's PIN, sent as `pin`. */
  | { kind: 'pin'; pin: string }
  /** `pin_setup` (spec/03 §4.18): the new PIN, sent as `pin` + `pin_confirm`. */
  | { kind: 'pinSetup'; pin: string; confirm: string }
  /** Declines a skippable required action for this login ("Not now"). */
  | { kind: 'skip' }
  /**
   * Any other answer, e.g. for an extension challenge type (spec/03 §4.16). Sent through the native
   * pipeline (DPoP, nonce retry, `auth_session` rotation, code exchange).
   */
  | { kind: 'custom'; fields: { name: string; value: string }[] };

/** The challenge types an answer kind can be sent for (`skip` and `custom`: any). */
export const answerChallengeType: Record<
  Exclude<ChallengeAnswer['kind'], 'skip' | 'custom'>,
  KnownChallengeType
> = {
  username: 'username',
  password: 'password',
  totp: 'totp',
  otp: 'otp',
  otpResend: 'otp',
  recoveryCode: 'recovery_code',
  updatePassword: 'update_password',
  verifyEmail: 'verify_email',
  verifyEmailResend: 'verify_email',
  terms: 'terms',
  pushResend: 'push',
  pushPoll: 'push',
  pushEnrollmentCheck: 'push_enrollment',
  pin: 'pin',
  pinSetup: 'pin_setup',
};

// MARK: - Errors

/** The SDKs' error codes (spec/05 §2.3); server codes pass through, so the list is not closed. */
export const NativeAuthErrorCode = {
  invalidRequest: 'invalid_request',
  invalidSession: 'invalid_session',
  invalidDPoPProof: 'invalid_dpop_proof',
  invalidClient: 'invalid_client',
  accessDenied: 'access_denied',
  slowDown: 'slow_down',
  serverError: 'server_error',
  redirectToWeb: 'redirect_to_web',
  invalidToken: 'invalid_token',
  insufficientAuthorization: 'insufficient_authorization',
  invalidGrant: 'invalid_grant',
  networkError: 'network_error',
  invalidResponse: 'invalid_response',
  metadataUnavailable: 'metadata_unavailable',
  unsupportedChallenge: 'unsupported_challenge',
  flowState: 'flow_state',
  invalidParameter: 'invalid_parameter',
  passkeyCancelled: 'passkey_cancelled',
  passkeyFailed: 'passkey_failed',
  passkeyUnavailable: 'passkey_unavailable',
  rpIdMismatch: 'rp_id_mismatch',
  credentialsNotFound: 'credentials_not_found',
  reauthenticationRequired: 'reauthentication_required',
  keychainError: 'keychain_error',
  keychainAuthenticationFailed: 'keychain_authentication_failed',
  dpopKeyError: 'dpop_key_error',
  webFallbackCancelled: 'web_fallback_cancelled',
  webFallbackFailed: 'web_fallback_failed',
  savedPasswordCancelled: 'saved_password_cancelled',
  savedPasswordUnavailable: 'saved_password_unavailable',
  /** Push: no usable native login for the device API (sign in with DPoP first). */
  deviceTokenUnavailable: 'device_token_unavailable',
  /** Push: this device is not enrolled. */
  pushNotEnrolled: 'push_not_enrolled',
  /** Push: the server advertises no push block (the extension is not installed). */
  pushUnavailable: 'push_unavailable',
  /** Push: the approval was resolved meanwhile. */
  pushConflict: 'push_conflict',
  /** Push: the picked number or the PIN was wrong; one more try. */
  userVerificationMismatch: 'user_verification_mismatch',
  /** The module is used before `configure`, or the native module is missing. */
  notConfigured: 'not_configured',
} as const;

/** The single error type (spec/05 §2.3): branch on `code`, never on the message. */
export class NativeAuthError extends Error {
  readonly code: string;
  readonly statusCode?: number;
  readonly errorDescription?: string;
  readonly isNetworkError: boolean;
  readonly isRetryable: boolean;
  /** `Retry-After` in seconds for `slow_down`. */
  readonly retryAfter?: number;

  constructor(
    code: string,
    errorDescription?: string,
    extra: {
      statusCode?: number;
      isNetworkError?: boolean;
      isRetryable?: boolean;
      retryAfter?: number;
    } = {}
  ) {
    super(errorDescription ?? code);
    this.name = 'NativeAuthError';
    this.code = code;
    this.errorDescription = errorDescription;
    this.statusCode = extra.statusCode;
    this.isNetworkError = extra.isNetworkError ?? false;
    this.isRetryable = extra.isRetryable ?? false;
    this.retryAfter = extra.retryAfter;
  }

  /** Converts a rejection of the native module (`code` + `userInfo`) into a `NativeAuthError`. */
  static from(error: unknown): NativeAuthError {
    if (error instanceof NativeAuthError) return error;
    const e = (error ?? {}) as {
      code?: unknown;
      message?: unknown;
      userInfo?: Record<string, unknown> | null;
    };
    const info = e.userInfo ?? {};
    const n = (v: unknown) => (typeof v === 'number' ? v : undefined);
    return new NativeAuthError(
      typeof e.code === 'string' && e.code.length > 0
        ? e.code
        : NativeAuthErrorCode.invalidResponse,
      typeof e.message === 'string' ? e.message : undefined,
      {
        statusCode: n(info.statusCode),
        isNetworkError: info.isNetworkError === true,
        isRetryable: info.isRetryable === true,
        retryAfter: n(info.retryAfter),
      }
    );
  }
}

// MARK: - Passwords and passkeys outside a flow

/** A password picked from the system sheet (`kc.pickSavedPassword()`). */
export interface SavedPassword {
  username: string;
  password: string;
}

/** A passkey registered through the authenticated endpoints (`kc.registerNewPasskey`). */
export interface RegisteredPasskey {
  credentialId: string;
  label?: string;
}

// MARK: - Push MFA (spec/03 §7)

/**
 * Where push messages reach this device: the server's sender and the token it addresses. `fcm` with
 * the FCM registration token, `apns` with the hex APNs device token, `none` (no delivery: the app reads
 * its pending approvals itself).
 */
export interface PushProviderRegistration {
  type: 'fcm' | 'apns' | 'none' | (string & {});
  id?: string;
}

/** The stored push enrollment of this device. */
export interface PushEnrollment {
  credentialId: string;
  deviceId: string;
  userId: string;
  username?: string;
  deviceLabel: string;
  pushProviderType: string;
  pushProviderId?: string;
  deviceApiBase: string;
  keyThumbprint: string;
  /** Epoch milliseconds. */
  enrolledAt?: number;
}

export function parsePushEnrollment(
  json: JsonValue | undefined
): PushEnrollment | undefined {
  const o = asObject(json);
  const credentialId = str(o?.credentialId);
  const deviceId = str(o?.deviceId);
  const userId = str(o?.userId);
  if (o === undefined || !credentialId || !deviceId || !userId)
    return undefined;
  return {
    credentialId,
    deviceId,
    userId,
    username: str(o.username),
    deviceLabel: str(o.deviceLabel) ?? '',
    pushProviderType: str(o.pushProviderType) ?? 'none',
    pushProviderId: str(o.pushProviderId),
    deviceApiBase: str(o.deviceApiBase) ?? '',
    keyThumbprint: str(o.keyThumbprint) ?? '',
    enrolledAt: num(o.enrolledAt),
  };
}

/** One entry of `GET /push-mfa/login/pending` (spec/03 §7). */
export interface PendingApproval {
  cid: string;
  userId?: string;
  username?: string;
  clientId?: string;
  clientName?: string;
  /** Epoch milliseconds. */
  createdAt?: number;
  expiresAt?: number;
  /** Number match: the numbers to offer; the other screen shows one of them. */
  numbers: string[];
  /** `pin` user verification: the user types the PIN the other side shows. */
  requiresPin: boolean;
  /** The client's display name, else its id. */
  clientDisplayName: string;
  raw: JsonObject;
}

export function parsePendingApproval(
  json: JsonValue
): PendingApproval | undefined {
  const o = asObject(json);
  const cid = str(o?.cid);
  if (o === undefined || cid === undefined) return undefined;
  const verification = asObject(o.userVerification);
  const clientName = str(o.clientName);
  const clientId = str(o.clientId);
  return {
    cid,
    userId: str(o.userId),
    username: str(o.username),
    clientId,
    clientName,
    createdAt: epochMillis(o.createdAt),
    expiresAt: epochMillis(o.expiresAt),
    numbers: arr(verification?.numbers).flatMap((n) =>
      typeof n === 'number' ? [String(n)] : typeof n === 'string' ? [n] : []
    ),
    requiresPin: str(verification?.type) === 'pin',
    clientDisplayName: clientName ?? clientId ?? '?',
    raw: o,
  };
}

/** Whether an approval has expired (`expiresAt` passed). */
export function isApprovalExpired(
  approval: PendingApproval,
  now: number = Date.now()
): boolean {
  return approval.expiresAt !== undefined && approval.expiresAt <= now;
}

/** The push-MFA keys of a notification (`push.handleMessage`). */
export interface PushNotificationPayload {
  cid: string;
  credentialId?: string;
  /** Epoch milliseconds. */
  expiresAt?: number;
}

export function parsePushNotificationPayload(
  json: JsonValue | undefined
): PushNotificationPayload | undefined {
  const o = asObject(json);
  const cid = str(o?.cid);
  if (o === undefined || cid === undefined) return undefined;
  return {
    cid,
    credentialId: str(o.credentialId),
    expiresAt: num(o.expiresAt),
  };
}

/** The device's answer to a pending approval. */
export type PushApprovalAction =
  | {
      kind: 'approve';
      /** The picked number (number match) or the typed PIN. */
      userVerification?: string;
    }
  | { kind: 'deny' };
