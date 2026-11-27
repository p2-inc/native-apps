import { NativeAuthError, NativeAuthErrorCode } from './errors';
import {
  base64UrlEncode,
  bufferSource,
  randomId,
  sha256,
  subtle,
  utf8,
} from './encoding';
import type { KeyValueStore } from './storage';
import { header, responseJson, type HttpResponse } from './transport';
import { asObject, str } from './json';

/**
 * `automatic` and `enabled` both sign every challenge and token request with an ES256 key created
 * by WebCrypto as non-extractable: the private key never leaves the browser, and a token copied off
 * the page is useless without it (spec/03 §8, spec/22). `disabled` sends no proofs.
 */
export type DPoPMode = 'automatic' | 'enabled' | 'disabled';

interface StoredKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface EcPublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/** RFC 7638 thumbprint (`jkt`) of a P-256 public key. */
export async function jwkThumbprint(jwk: EcPublicJwk): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return base64UrlEncode(await sha256(canonical));
}

/** `htu`: scheme, host, port and path only, no query or fragment (RFC 9449 §4.2). */
export function htu(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host}${u.pathname}`;
}

/**
 * Owns the DPoP key (created on first use, kept in the store as non-extractable `CryptoKey`s),
 * builds proofs and remembers server nonces per origin.
 */
export class DPoPSigner {
  private key: Promise<{ pair: StoredKey; jwk: EcPublicJwk }> | undefined;
  private readonly nonces = new Map<string, string>();

  constructor(
    private readonly store: KeyValueStore,
    private readonly storeKey: string,
    private readonly warn: (message: string) => void = () => {}
  ) {}

  /** A proof JWT for `method url`, with `ath` when `accessToken` is given. */
  async proof(
    method: string,
    url: string,
    accessToken?: string,
    extraClaims: Record<string, unknown> = {}
  ): Promise<string> {
    const { pair, jwk } = await this.currentKey();
    const headerJson = { typ: 'dpop+jwt', alg: 'ES256', jwk };
    const payload: Record<string, unknown> = {
      jti: randomId(),
      htm: method.toUpperCase(),
      htu: htu(url),
      iat: Math.floor(Date.now() / 1000),
    };
    if (accessToken !== undefined)
      payload.ath = base64UrlEncode(await sha256(accessToken));
    const nonce = this.nonces.get(new URL(url).origin);
    if (nonce !== undefined) payload.nonce = nonce;
    for (const [claim, value] of Object.entries(extraClaims)) {
      if (!(claim in payload)) payload[claim] = value;
    }
    const signingInput = `${base64UrlEncode(utf8(JSON.stringify(headerJson)))}.${base64UrlEncode(utf8(JSON.stringify(payload)))}`;
    const signature = await subtle().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      bufferSource(utf8(signingInput))
    );
    // WebCrypto returns the IEEE P1363 (r || s) form JWS wants.
    return `${signingInput}.${base64UrlEncode(signature)}`;
  }

  async publicJwk(): Promise<EcPublicJwk> {
    return (await this.currentKey()).jwk;
  }

  async thumbprint(): Promise<string> {
    return jwkThumbprint(await this.publicJwk());
  }

  setNonce(nonce: string, url: string): void {
    this.nonces.set(new URL(url).origin, nonce);
  }

  /** Forgets the key (sign-out): tokens bound to it stop working. */
  async reset(): Promise<void> {
    this.key = undefined;
    this.nonces.clear();
    try {
      await this.store.remove(this.storeKey);
    } catch (e) {
      this.warn(`Could not remove the stored DPoP key: ${String(e)}`);
    }
  }

  private currentKey(): Promise<{ pair: StoredKey; jwk: EcPublicJwk }> {
    if (this.key === undefined) {
      this.key = this.loadOrCreate();
      this.key.catch(() => {
        this.key = undefined;
      });
    }
    return this.key;
  }

  private async loadOrCreate(): Promise<{ pair: StoredKey; jwk: EcPublicJwk }> {
    let stored: StoredKey | undefined;
    try {
      stored = await this.store.get<StoredKey>(this.storeKey);
    } catch (e) {
      this.warn(`Could not read the stored DPoP key, creating a new one: ${String(e)}`);
    }
    if (stored?.privateKey !== undefined && stored.publicKey !== undefined) {
      try {
        return { pair: stored, jwk: await exportPublic(stored.publicKey) };
      } catch (e) {
        this.warn(`Stored DPoP key is unusable, creating a new one: ${String(e)}`);
      }
    }
    let pair: CryptoKeyPair;
    try {
      pair = (await subtle().generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      )) as CryptoKeyPair;
    } catch (e) {
      throw new NativeAuthError(
        NativeAuthErrorCode.dpopKeyError,
        `DPoP key creation failed: ${String(e)}`,
        { cause: e }
      );
    }
    const record: StoredKey = { privateKey: pair.privateKey, publicKey: pair.publicKey };
    try {
      await this.store.set(this.storeKey, record);
    } catch (e) {
      this.warn(`Could not persist the DPoP key; it lives in memory only: ${String(e)}`);
    }
    return { pair: record, jwk: await exportPublic(pair.publicKey) };
  }

  /** RFC 9449 §8: `400 use_dpop_nonce` (or `401` on resource servers) with a `DPoP-Nonce` header. */
  static nonceChallenge(response: HttpResponse): string | undefined {
    const nonce = header(response, 'dpop-nonce');
    if (nonce === undefined) return undefined;
    if (response.status === 400) {
      return str(asObject(responseJson(response))?.error) === 'use_dpop_nonce'
        ? nonce
        : undefined;
    }
    if (response.status === 401) {
      return /use_dpop_nonce/.test(header(response, 'www-authenticate') ?? '')
        ? nonce
        : undefined;
    }
    return undefined;
  }
}

async function exportPublic(publicKey: CryptoKey): Promise<EcPublicJwk> {
  const jwk = await subtle().exportKey('jwk', publicKey);
  if (jwk.x === undefined || jwk.y === undefined) {
    throw new Error('DPoP public key has no coordinates');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
