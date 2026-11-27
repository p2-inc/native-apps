import { DPoPSigner } from './dpop';
import { base64UrlDecode, base64UrlEncode, bufferSource } from './encoding';
import { NativeAuthError, NativeAuthErrorCode } from './errors';
import { asObject, str } from './json';
import type { MetadataClient } from './metadata';
import type {
  PasskeyAssertion,
  PasskeyAssertionParams,
  PasskeyAttestation,
  PasskeyRegistrationParams,
} from './model';
import { parseChallenge } from './model';
import { authorizationScheme, isDPoPBound, type Credentials } from './tokens';
import { responseJson, type HttpResponse, type Transport } from './transport';

/**
 * The platform half of passkeys: produce an assertion or an attestation from the server's params.
 * `BrowserPasskeyPlatform` uses `navigator.credentials`; tests inject a mock. Cancellation surfaces
 * as `passkey_cancelled`, never as a flow failure.
 */
export interface PasskeyPlatform {
  assert(
    params: PasskeyAssertionParams,
    options?: { mediation?: 'conditional' | 'optional'; signal?: AbortSignal }
  ): Promise<PasskeyAssertion>;
  register(params: PasskeyRegistrationParams): Promise<PasskeyAttestation>;
  /** Whether the browser can offer passkeys in the username field's autofill. */
  supportsConditionalMediation(): Promise<boolean>;
}

function decode(value: string, what: string): ArrayBuffer {
  const bytes = base64UrlDecode(value);
  if (bytes === undefined) {
    throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, `${what} is not base64url`);
  }
  return bufferSource(bytes);
}

/** Maps a WebAuthn `DOMException` to the SDK's codes. */
export function passkeyError(e: unknown): NativeAuthError {
  const name = e instanceof Error ? e.name : '';
  const message = e instanceof Error ? e.message : String(e);
  switch (name) {
    case 'NotAllowedError':
    case 'AbortError':
      // The user closed the prompt, or it timed out: the challenge set stays (spec/12 D4).
      return new NativeAuthError(NativeAuthErrorCode.passkeyCancelled, message, { cause: e });
    case 'SecurityError':
      return new NativeAuthError(
        NativeAuthErrorCode.rpIdMismatch,
        `The passkey RP ID does not match this page's domain: ${message}`,
        { cause: e }
      );
    case 'NotSupportedError':
      return new NativeAuthError(NativeAuthErrorCode.passkeyUnavailable, message, { cause: e });
    default:
      return new NativeAuthError(NativeAuthErrorCode.passkeyFailed, message, { cause: e });
  }
}

const TRANSPORTS = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card']);

export class BrowserPasskeyPlatform implements PasskeyPlatform {
  async supportsConditionalMediation(): Promise<boolean> {
    const pkc = globalThis.PublicKeyCredential as
      | (typeof PublicKeyCredential & { isConditionalMediationAvailable?: () => Promise<boolean> })
      | undefined;
    if (pkc?.isConditionalMediationAvailable === undefined) return false;
    try {
      return await pkc.isConditionalMediationAvailable();
    } catch {
      return false;
    }
  }

  async assert(
    params: PasskeyAssertionParams,
    options: { mediation?: 'conditional' | 'optional'; signal?: AbortSignal } = {}
  ): Promise<PasskeyAssertion> {
    const credentials = navigatorCredentials();
    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: decode(params.challenge, 'challenge'),
      rpId: params.rpId,
      userVerification: params.userVerification as UserVerificationRequirement,
      allowCredentials: params.allowCredentials.map((c) => ({
        type: 'public-key',
        id: decode(c.id, 'credential id'),
        transports: c.transports.filter((t) => TRANSPORTS.has(t)) as AuthenticatorTransport[],
      })),
      ...(params.timeoutMilliseconds ? { timeout: params.timeoutMilliseconds } : {}),
    };
    let credential: Credential | null;
    try {
      credential = await credentials.get({
        publicKey,
        ...(options.mediation === 'conditional' ? { mediation: 'conditional' as CredentialMediationRequirement } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
      });
    } catch (e) {
      throw passkeyError(e);
    }
    const pk = credential as PublicKeyCredential | null;
    const response = pk?.response as AuthenticatorAssertionResponse | undefined;
    if (pk === null || response === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.passkeyCancelled, 'No passkey was chosen');
    }
    return {
      credentialId: base64UrlEncode(pk.rawId),
      clientDataJson: base64UrlEncode(response.clientDataJSON),
      authenticatorData: base64UrlEncode(response.authenticatorData),
      signature: base64UrlEncode(response.signature),
      ...(response.userHandle && response.userHandle.byteLength > 0
        ? { userHandle: base64UrlEncode(response.userHandle) }
        : {}),
    };
  }

  async register(params: PasskeyRegistrationParams): Promise<PasskeyAttestation> {
    const credentials = navigatorCredentials();
    const residentKey = (params.residentKey ??
      (params.requireResidentKey ? 'required' : 'preferred')) as ResidentKeyRequirement;
    const publicKey: PublicKeyCredentialCreationOptions = {
      challenge: decode(params.challenge, 'challenge'),
      rp: { id: params.rp.id, name: params.rp.name ?? params.rp.id },
      user: {
        id: decode(params.user.id, 'user id'),
        name: params.user.name,
        displayName: params.user.displayName ?? params.user.name,
      },
      pubKeyCredParams: (params.pubKeyCredParams.length > 0 ? params.pubKeyCredParams : [-7, -257]).map(
        (alg) => ({ type: 'public-key' as const, alg })
      ),
      authenticatorSelection: {
        residentKey,
        requireResidentKey: residentKey === 'required',
        userVerification: params.userVerification as UserVerificationRequirement,
        ...(params.authenticatorAttachment &&
        params.authenticatorAttachment !== 'not specified'
          ? { authenticatorAttachment: params.authenticatorAttachment as AuthenticatorAttachment }
          : {}),
      },
      attestation: params.attestation as AttestationConveyancePreference,
      excludeCredentials: params.excludeCredentials.map((id) => ({
        type: 'public-key' as const,
        id: decode(id, 'excluded credential id'),
      })),
      ...(params.timeoutMilliseconds ? { timeout: params.timeoutMilliseconds } : {}),
    };
    let credential: Credential | null;
    try {
      credential = await credentials.create({ publicKey });
    } catch (e) {
      throw passkeyError(e);
    }
    const pk = credential as PublicKeyCredential | null;
    const response = pk?.response as AuthenticatorAttestationResponse | undefined;
    if (pk === null || response === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.passkeyCancelled, 'No passkey was created');
    }
    const transports =
      typeof response.getTransports === 'function' ? response.getTransports() : [];
    return {
      credentialId: base64UrlEncode(pk.rawId),
      clientDataJson: base64UrlEncode(response.clientDataJSON),
      attestationObject: base64UrlEncode(response.attestationObject),
      transports,
    };
  }
}

function navigatorCredentials(): CredentialsContainer {
  const credentials = typeof navigator === 'undefined' ? undefined : navigator.credentials;
  if (credentials === undefined || typeof PublicKeyCredential === 'undefined') {
    throw new NativeAuthError(
      NativeAuthErrorCode.passkeyUnavailable,
      'This browser does not support passkeys (WebAuthn), or the page is not a secure context'
    );
  }
  return credentials;
}

/** Result of a §6 registration. */
export interface RegisteredPasskey {
  credentialId: string;
  label?: string;
}

/** `POST /native-auth/passkey/register/options` and `/finish` with the user's access token (spec/03 §6). */
export class PasskeyRegistrationClient {
  constructor(
    private readonly issuer: string,
    private readonly metadata: MetadataClient,
    private readonly transport: Transport,
    private readonly dpop: DPoPSigner | undefined
  ) {}

  async options(
    credentials: Credentials
  ): Promise<{ registrationId: string; params: PasskeyRegistrationParams }> {
    const url =
      (await this.metadata.metadata()).passkey?.registerOptionsEndpoint ??
      `${this.issuer}/native-auth/passkey/register/options`;
    const response = await this.send('POST', url, undefined, credentials);
    const json = asObject(responseJson(response));
    if (response.status !== 200 || json === undefined) throw registrationError(response);
    const registrationId = str(json.registration_id);
    // The options body has the passkey_registration params shape (spec/03 §6).
    const challenge = parseChallenge({ type: 'passkey_registration', id: 'options', params: json });
    const params = challenge?.type === 'passkey_registration' ? challenge.params : undefined;
    if (registrationId === undefined || params === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, 'Registration options are incomplete', {
        statusCode: 200,
        details: json,
      });
    }
    return { registrationId, params };
  }

  async finish(
    credentials: Credentials,
    registrationId: string,
    attestation: PasskeyAttestation,
    label?: string
  ): Promise<RegisteredPasskey> {
    const url =
      (await this.metadata.metadata()).passkey?.registerFinishEndpoint ??
      `${this.issuer}/native-auth/passkey/register/finish`;
    const body: Record<string, unknown> = {
      credential_id: attestation.credentialId,
      client_data_json: attestation.clientDataJson,
      attestation_object: attestation.attestationObject,
      transports: attestation.transports,
      registration_id: registrationId,
    };
    if (label) body.label = label;
    const response = await this.send('POST', url, JSON.stringify(body), credentials);
    const json = asObject(responseJson(response));
    if ((response.status !== 201 && response.status !== 200) || json === undefined) {
      throw registrationError(response);
    }
    const credentialId = str(json.credential_id);
    if (credentialId === undefined) {
      throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, 'finish response without credential_id', {
        statusCode: response.status,
        details: json,
      });
    }
    return { credentialId, label: str(json.label) };
  }

  private async send(
    method: string,
    url: string,
    body: string | undefined,
    credentials: Credentials
  ): Promise<HttpResponse> {
    let response = await this.transport.send(await this.request(method, url, body, credentials));
    const nonce =
      this.dpop !== undefined && isDPoPBound(credentials) ? DPoPSigner.nonceChallenge(response) : undefined;
    if (nonce !== undefined) {
      this.dpop!.setNonce(nonce, url);
      response = await this.transport.send(await this.request(method, url, body, credentials));
    }
    return response;
  }

  private async request(method: string, url: string, body: string | undefined, credentials: Credentials) {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    headers.Authorization = `${authorizationScheme(credentials)} ${credentials.accessToken}`;
    if (isDPoPBound(credentials) && this.dpop !== undefined) {
      headers.DPoP = await this.dpop.proof(method, url, credentials.accessToken);
    }
    return { method, url, headers, ...(body !== undefined ? { body } : {}) };
  }
}

function registrationError(response: HttpResponse): NativeAuthError {
  if (response.status === 401) return NativeAuthError.fromResponse(response, NativeAuthErrorCode.invalidToken);
  if (response.status === 403)
    return NativeAuthError.fromResponse(response, NativeAuthErrorCode.insufficientAuthorization);
  return NativeAuthError.fromResponse(response);
}
