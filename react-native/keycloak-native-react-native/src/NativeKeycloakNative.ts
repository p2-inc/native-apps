import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * The TurboModule (spec/19 §4). Codegen generates the Kotlin and Objective-C++ bindings from this file.
 *
 * Structured values cross the bridge as JSON strings: challenge `params` are open-ended JSON
 * (spec/03 §10: clients ignore unknown fields), so the native side forwards the descriptors as the
 * server sent them and `src/model.ts` builds the typed views. The native side keeps the authoritative
 * objects (the flow, its PKCE verifier and DPoP key, the pending challenges, the full credentials);
 * JavaScript holds opaque ids for them. The refresh token and the post-login `auth_session` never
 * cross the bridge.
 *
 * Errors reject with the SDK's `NativeAuthError` code as the promise's `code` (spec/05 §2.3) and
 * `statusCode`, `isNetworkError`, `isRetryable`, `retryAfter` in `userInfo`.
 */
export interface Spec extends TurboModule {
  /** Creates or replaces the SDK instance `instanceId` (one per issuer + client). `config`: `NativeConfig`. */
  configure(instanceId: string, config: string): Promise<void>;

  /**
   * A new flow (nothing is sent yet): `startLogin`, or `stepUp` with the stored post-login session when
   * `stepUp` is true. `parameters`: `LoginParameters`. Resolves to the flow id.
   */
  createFlow(
    instanceId: string,
    parameters: string,
    stepUp: boolean
  ): Promise<string>;

  /** `flow.start()`; resolves to a `NativeFlowStep` JSON. */
  start(flowId: string): Promise<string>;

  /**
   * `flow.respond(answer, challenge, additionalFields)` for the pending challenge with this id and
   * wire type. `answer`: `ChallengeAnswer` JSON; `additionalFields`: a JSON object of strings.
   */
  respond(
    flowId: string,
    challengeId: string,
    challengeType: string,
    answer: string,
    additionalFields: string
  ): Promise<string>;

  /**
   * Runs the platform passkey prompt for the pending `passkey` challenge (`kc.passkeys().assert`) and
   * answers it with the assertion, in one call: WebAuthn material never crosses the bridge.
   */
  respondWithPasskey(
    flowId: string,
    challengeId: string,
    preferImmediatelyAvailableCredentials: boolean
  ): Promise<string>;

  /**
   * Runs the platform registration for the pending `passkey_registration` challenge
   * (`kc.passkeys().register`) and answers it. `label`: the passkey's name, empty for none.
   */
  respondWithPasskeyRegistration(
    flowId: string,
    challengeId: string,
    label: string
  ): Promise<string>;

  /**
   * Answers the pending `push_enrollment` challenge with a device JWT signed by the DPoP key
   * (`push.prepareEnrollment`) and stores the enrollment once the server accepted it. `pushProviderId`
   * is empty for the `none` provider.
   */
  respondWithPushEnrollment(
    flowId: string,
    challengeId: string,
    deviceLabel: string,
    pushProviderType: string,
    pushProviderId: string
  ): Promise<string>;

  /** `flow.cancel()`: best-effort server cancellation. */
  cancel(flowId: string): Promise<void>;

  /** Runs the browser fallback for the flow's last `redirectToWeb` step; resolves to `NativeCredentials` JSON. */
  completeWebFallback(flowId: string): Promise<string>;

  /** Persists the credentials the flow ended with (its `authorized` step or the browser fallback). */
  storeCredentials(flowId: string): Promise<void>;

  /** Forgets the flow on the native side. */
  releaseFlow(flowId: string): void;

  /** `credentialsManager().credentials(minTtl)`: stored credentials, refreshed when needed. */
  credentials(instanceId: string, minTtlSeconds: number): Promise<string>;

  /** `credentialsManager().stored()`: possibly expired credentials, or null. */
  storedCredentials(instanceId: string): Promise<string | null>;

  hasValidCredentials(
    instanceId: string,
    minTtlSeconds: number
  ): Promise<boolean>;

  /**
   * Headers for a resource request with the stored credentials (refreshed when needed): `Authorization`,
   * plus a `DPoP` proof bound to this method and URL when the tokens are DPoP-bound. A JSON object.
   */
  resourceRequestHeaders(
    instanceId: string,
    method: string,
    url: string
  ): Promise<string>;

  /** `credentialsManager().logout()`: server logout with the stored refresh token, then clear. */
  logout(instanceId: string): Promise<void>;

  clearCredentials(instanceId: string): Promise<void>;

  /** The server's native-auth metadata document, as received. */
  metadata(instanceId: string, forceRefresh: boolean): Promise<string>;

  /** RFC 7638 thumbprint of the DPoP key (`jkt`), null when DPoP is disabled. */
  dpopKeyThumbprint(instanceId: string): Promise<string | null>;

  // Passwords and passkeys outside a flow

  /** The system sheet of saved passwords; resolves to `{username, password}` JSON. */
  pickSavedPassword(instanceId: string): Promise<string>;

  /**
   * Offers a login to the password manager (Android Credential Manager). iOS saves through AutoFill
   * and resolves without doing anything.
   */
  savePassword(
    instanceId: string,
    username: string,
    password: string
  ): Promise<void>;

  /**
   * Registers a passkey for the signed-in user through the authenticated registration endpoints
   * (`passkeys().registerNewPasskey`); resolves to `{credentialId, label}` JSON. `label` empty for none.
   */
  registerNewPasskey(instanceId: string, label: string): Promise<string>;

  // Push MFA (spec/03 §7), the device side (`kc.push()`)

  /** The stored enrollment of this device as JSON, or null. */
  pushEnrollment(instanceId: string): Promise<string | null>;

  /** In-app enrollment (`push.enroll`); resolves to the enrollment JSON. `pushProviderId` empty for `none`. */
  pushEnroll(
    instanceId: string,
    deviceLabel: string,
    pushProviderType: string,
    pushProviderId: string
  ): Promise<string>;

  pushForgetEnrollment(instanceId: string): Promise<void>;

  /** `GET …/login/pending`: a JSON array of the pending approvals as the server sent them. */
  pushPendingApprovals(instanceId: string): Promise<string>;

  /**
   * Approves (`approve`) or denies (`deny`) a pending approval; `userVerification` is the picked number
   * or the PIN, empty for none. Resolves to the server's status.
   */
  pushRespond(
    instanceId: string,
    cid: string,
    action: string,
    userVerification: string
  ): Promise<string>;

  /**
   * Decodes a push-MFA message (the data map of an FCM message, or the APNs `userInfo`) as a JSON
   * object of strings; resolves to the payload JSON, or null when it is not one for this device.
   */
  pushHandleMessage(instanceId: string, data: string): Promise<string | null>;

  /** `PUT …/device/push-provider` (`fcm` + registration token, `apns` + hex device token, `none`). */
  pushUpdateProvider(
    instanceId: string,
    pushProviderType: string,
    pushProviderId: string
  ): Promise<void>;

  /** `PUT …/device/rotate-key`; clears the stored credentials (a new login binds the new key). */
  pushRotateKey(instanceId: string): Promise<void>;

  /** `POST …/login/lockout`: the panic button; the server disables the account. */
  pushLockout(instanceId: string): Promise<void>;
}

// `get`, not `getEnforcing`: the package can be imported where the binary is absent (Jest, the web)
// and fails with `not_configured` on first use instead.
export default TurboModuleRegistry.get<Spec>('KeycloakNative');
