import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DPoPSigner,
  IndexedDBStore,
  KeycloakWeb,
  MemoryStore,
  NativeAuthErrorCode,
  base64UrlDecode,
  bufferSource,
  callbackCode,
  decodeJwtPayload,
  fromUtf8,
  htu,
  jwkThumbprint,
  parseWwwAuthenticate,
  sha256,
  base64UrlEncode,
  utf8,
  type Credentials,
} from '../src';
import { expectError } from './support';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('DPoP', () => {
  it('signs RFC 9449 proofs with a non-extractable P-256 key that survives a reload', async () => {
    const store = new MemoryStore();
    const signer = new DPoPSigner(store, 'k');
    const proof = await signer.proof('post', 'https://idp.example.com/realms/demo/native-auth/challenge?x=1#y', 'token-123');
    const [h, p, sig] = proof.split('.');
    const header = JSON.parse(fromUtf8(base64UrlDecode(h!)!));
    const payload = decodeJwtPayload(proof)!;
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(Object.keys(header.jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe('https://idp.example.com/realms/demo/native-auth/challenge');
    expect(payload.ath).toBe(base64UrlEncode(await sha256('token-123')));
    expect(typeof payload.jti).toBe('string');

    // The signature verifies with the embedded public key.
    const key = await crypto.subtle.importKey('jwk', header.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      bufferSource(base64UrlDecode(sig!)!),
      bufferSource(utf8(`${h}.${p}`))
    );
    expect(valid).toBe(true);

    // The private key cannot be exported, and a new signer over the same store reuses it.
    const stored = await store.get<{ privateKey: CryptoKey }>('k');
    expect(stored!.privateKey.extractable).toBe(false);
    const again = new DPoPSigner(store, 'k');
    expect(await again.thumbprint()).toBe(await signer.thumbprint());
    expect(await signer.thumbprint()).toBe(await jwkThumbprint(header.jwk));
  });

  it('includes the server nonce for its origin only', async () => {
    const signer = new DPoPSigner(new MemoryStore(), 'k');
    signer.setNonce('n-1', 'https://a.example/x');
    expect(decodeJwtPayload(await signer.proof('GET', 'https://a.example/y'))!.nonce).toBe('n-1');
    expect(decodeJwtPayload(await signer.proof('GET', 'https://b.example/y'))!.nonce).toBeUndefined();
    expect(htu('https://a.example:8443/p?q')).toBe('https://a.example:8443/p');
  });

  it('reads the nonce challenge of a token endpoint and of a resource server', () => {
    expect(
      DPoPSigner.nonceChallenge({ status: 400, headers: { 'dpop-nonce': 'n' }, body: '{"error":"use_dpop_nonce"}' })
    ).toBe('n');
    expect(
      DPoPSigner.nonceChallenge({
        status: 401,
        headers: { 'dpop-nonce': 'n', 'www-authenticate': 'DPoP error="use_dpop_nonce"' },
        body: '',
      })
    ).toBe('n');
    expect(DPoPSigner.nonceChallenge({ status: 400, headers: {}, body: '{"error":"use_dpop_nonce"}' })).toBeUndefined();
  });
});

describe('IndexedDB store', () => {
  it('round-trips values, CryptoKeys included', async () => {
    const store = new IndexedDBStore('test-db');
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])) as CryptoKeyPair;
    await store.set('a', { refreshToken: 'r', n: 1 });
    expect(await store.get('a')).toEqual({ refreshToken: 'r', n: 1 });
    await store.remove('a');
    expect(await store.get('a')).toBeUndefined();
    await store.set('key', { privateKey: pair.privateKey });
    const back = await store.get<{ privateKey: CryptoKey }>('key');
    expect(back?.privateKey.type).toBe('private');
  });
});

describe('WWW-Authenticate and callbacks', () => {
  it('parses RFC 9470 step-up challenges', () => {
    expect(
      parseWwwAuthenticate(
        'Bearer error="insufficient_user_authentication", error_description="A different authentication level is required", acr_values="gold", max_age=300'
      )
    ).toEqual({
      error: 'insufficient_user_authentication',
      error_description: 'A different authentication level is required',
      acr_values: 'gold',
      max_age: '300',
    });
  });

  it('extracts the code and enforces state', async () => {
    expect(callbackCode('https://app.example/cb?state=s&code=c', 's')).toBe('c');
    expect(callbackCode('https://app.example/cb#state=s&code=c', 's')).toBe('c');
    expect(() => callbackCode('https://app.example/cb?state=x&code=c', 's')).toThrow();
    expect(() => callbackCode('https://app.example/cb?error=access_denied', 's')).toThrow(/browser flow failed|access_denied/);
  });
});

describe('kc.fetch', () => {
  function signedIn(dpop: 'automatic' | 'disabled' = 'disabled') {
    const kc = KeycloakWeb.configure({
      issuer: 'https://idp.example.com/realms/demo',
      clientId: 'web',
      storage: 'memory',
      dpop,
      transport: { send: async () => ({ status: 500, headers: {}, body: '' }) },
      onWarning: () => {},
    });
    const credentials: Credentials = {
      accessToken: 'at-1',
      tokenType: dpop === 'disabled' ? 'Bearer' : 'DPoP',
      expiresAt: Date.now() + 300_000,
      issuedAt: Date.now(),
      authSession: 'as',
    };
    return { kc, credentials };
  }

  it('adds the token and, on an RFC 9470 challenge, steps up and retries once', async () => {
    const { kc, credentials } = signedIn();
    await kc.credentialsManager().store(credentials);
    const calls: Request[] = [];
    let first = true;
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push(new Request(url, init));
      if (first) {
        first = false;
        return new Response('', {
          status: 401,
          headers: { 'WWW-Authenticate': 'Bearer error="insufficient_user_authentication", acr_values="2"' },
        });
      }
      return new Response('ok', { status: 200 });
    });
    const asked: unknown[] = [];
    kc.setStepUpHandler(async (request) => {
      asked.push(request);
      return true;
    });
    const response = await kc.fetch('https://api.example.com/payouts', { method: 'POST' });
    expect(response.status).toBe(200);
    expect(asked).toEqual([{ url: 'https://api.example.com/payouts', method: 'POST', acrValues: '2' }]);
    expect(calls).toHaveLength(2);
    expect(calls[0]!.headers.get('authorization')).toBe('Bearer at-1');
  });

  it('without a step-up handler the request fails with step_up_required', async () => {
    const { kc, credentials } = signedIn();
    await kc.credentialsManager().store(credentials);
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response('', {
          status: 403,
          headers: { 'WWW-Authenticate': 'Bearer error="insufficient_user_authentication", max_age=60' },
        })
    );
    expect((await expectError(() => kc.fetch('https://api.example.com/x'))).code).toBe(NativeAuthErrorCode.stepUpRequired);
  });

  it('sends a DPoP proof with ath for bound tokens', async () => {
    const { kc, credentials } = signedIn('automatic');
    await kc.credentialsManager().store(credentials);
    let seen: Headers | undefined;
    vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
      seen = new Headers(init.headers);
      return new Response('ok');
    });
    await kc.fetch('https://api.example.com/x?y=1');
    expect(seen!.get('authorization')).toBe('DPoP at-1');
    const proof = decodeJwtPayload(seen!.get('dpop')!)!;
    expect(proof.htu).toBe('https://api.example.com/x');
    expect(proof.ath).toBe(base64UrlEncode(await sha256('at-1')));
  });

  it('signed out: credentials_not_found', async () => {
    const { kc } = signedIn();
    expect((await expectError(() => kc.fetch('https://api.example.com/x'))).code).toBe(NativeAuthErrorCode.credentialsNotFound);
  });
});
