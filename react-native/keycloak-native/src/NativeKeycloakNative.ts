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
}

// `get`, not `getEnforcing`: the package can be imported where the binary is absent (Jest, the web)
// and fails with `not_configured` on first use instead.
export default TurboModuleRegistry.get<Spec>('KeycloakNative');
