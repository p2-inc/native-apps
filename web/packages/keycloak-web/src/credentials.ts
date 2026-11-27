import { NativeAuthError, NativeAuthErrorCode } from './errors';
import type { KeyValueStore } from './storage';
import { isExpired, type Credentials, type Tokens } from './tokens';

/**
 * What survives a reload (spec/22, "Security model"): the refresh token, bound by DPoP to a
 * non-extractable key, and the post-login `auth_session` for step-up. The access and ID tokens stay
 * in memory, as oidc-spa keeps them; a reload refreshes to get new ones.
 */
interface Persisted {
  refreshToken: string;
  refreshExpiresAt?: number;
  tokenType: string;
  scope?: string;
  authSession?: string;
}

export type AuthStateListener = (credentials: Credentials | undefined) => void;

/**
 * Holds the signed-in user's credentials: in memory, plus the persisted refresh token. Refreshes are
 * serialized in this tab and, through the Web Locks API, across tabs; a same-origin `BroadcastChannel`
 * hands other tabs the new tokens on sign-in and refresh, and tells them about sign-out.
 */
export class CredentialsManager {
  private current: Credentials | undefined;
  private refreshing: Promise<Credentials> | undefined;
  private readonly listeners = new Set<AuthStateListener>();
  private readonly channel: BroadcastChannel | undefined;

  constructor(
    private readonly kv: KeyValueStore,
    private readonly key: string,
    private readonly tokens: Tokens,
    private readonly warn: (message: string) => void = () => {},
    private readonly leewayMs = 30_000
  ) {
    // Tabs only: in workers and tests there is nobody to tell.
    this.channel =
      typeof window === 'undefined' || typeof BroadcastChannel === 'undefined'
        ? undefined
        : new BroadcastChannel(`keycloak-web:${key}`);
    this.channel?.addEventListener('message', (event: MessageEvent) => {
      const data = event.data as { type?: string; credentials?: Credentials } | undefined;
      if (data?.type === 'signed-out') {
        this.current = undefined;
        this.emit();
      } else if (data?.type === 'updated' && data.credentials !== undefined) {
        // Another tab of this origin signed in or refreshed: use its tokens (no request, no echo).
        this.current = data.credentials;
        this.emit();
      }
    });
  }

  /** The credentials in memory, possibly expired; `undefined` when signed out or not yet restored. */
  get snapshot(): Credentials | undefined {
    return this.current;
  }

  subscribe(listener: AuthStateListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  async store(credentials: Credentials): Promise<void> {
    this.current = credentials;
    await this.persist(credentials);
    this.channel?.postMessage({ type: 'updated', credentials });
    this.emit();
  }

  /** Whether a session can be restored: something in memory or a persisted refresh token. */
  async hasSession(): Promise<boolean> {
    if (this.current !== undefined) return true;
    return (await this.read()) !== undefined;
  }

  /** The stored post-login `auth_session`, for step-up (spec/03 §5). */
  async authSession(): Promise<string | undefined> {
    return this.current?.authSession ?? (await this.read())?.authSession;
  }

  /**
   * Valid credentials, refreshing when the access token is within the leeway plus `minTtlMs` of
   * expiry, or when only the persisted refresh token is left (after a reload). Throws
   * `credentials_not_found` when signed out and `reauthentication_required` when the refresh is
   * refused (the Keycloak session ended).
   */
  async credentials(minTtlMs = 0): Promise<Credentials> {
    const current = this.current;
    if (current !== undefined && !isExpired(current, this.leewayMs + minTtlMs)) return current;
    if (this.refreshing === undefined) {
      this.refreshing = this.withLock(() => this.refresh(minTtlMs)).finally(() => {
        this.refreshing = undefined;
      });
    }
    return this.refreshing;
  }

  /** Restores the session after a reload; `undefined` when there is none or it has ended. */
  async restore(): Promise<Credentials | undefined> {
    try {
      return await this.credentials();
    } catch (e) {
      const error = NativeAuthError.from(e);
      if (
        error.code === NativeAuthErrorCode.credentialsNotFound ||
        error.code === NativeAuthErrorCode.reauthenticationRequired
      ) {
        return undefined;
      }
      throw error;
    }
  }

  /** Forgets the credentials in this browser (all tabs). */
  async clear(): Promise<void> {
    this.current = undefined;
    try {
      await this.kv.remove(this.key);
    } catch (e) {
      this.warn(`Could not remove stored credentials: ${String(e)}`);
    }
    this.channel?.postMessage({ type: 'signed-out' });
    this.emit();
  }

  /**
   * Ends the Keycloak session with the refresh token, best effort, then clears. Server and network
   * failures are not thrown: the local state is cleared regardless.
   */
  async logout(): Promise<void> {
    const persisted = await this.read().catch(() => undefined);
    const refreshToken = this.current?.refreshToken ?? persisted?.refreshToken;
    const tokenType = this.current?.tokenType ?? persisted?.tokenType ?? 'Bearer';
    if (refreshToken !== undefined) {
      try {
        if (tokenType.toLowerCase() === 'dpop') {
          // Keycloak's logout endpoint refuses a DPoP-bound refresh token ("DPoP proof is missing"
          // even with a proof, through 26.8); revoking it with a proof ends the session.
          await this.tokens.revoke(refreshToken);
        } else {
          await this.tokens.logout(refreshToken);
        }
      } catch (e) {
        this.warn(`Server logout failed: ${String(e)}`);
      }
    }
    await this.clear();
  }

  private async refresh(minTtlMs: number): Promise<Credentials> {
    // Another tab may have refreshed while we waited for the lock.
    const persisted = await this.read();
    const current = this.current;
    if (current !== undefined && !isExpired(current, this.leewayMs + minTtlMs)) return current;
    if (persisted === undefined && current?.refreshToken === undefined) {
      if (current !== undefined) {
        // Signed in without a refresh token (the client issues none): nothing to refresh with.
        throw new NativeAuthError(
          NativeAuthErrorCode.reauthenticationRequired,
          'The access token expired and there is no refresh token'
        );
      }
      throw new NativeAuthError(NativeAuthErrorCode.credentialsNotFound, 'No stored credentials');
    }
    const base: Credentials = {
      accessToken: current?.accessToken ?? '',
      tokenType: persisted?.tokenType ?? current?.tokenType ?? 'Bearer',
      // The store wins: another tab may have rotated the refresh token.
      refreshToken: persisted?.refreshToken ?? current?.refreshToken,
      idToken: current?.idToken,
      scope: persisted?.scope ?? current?.scope,
      expiresAt: 0,
      refreshExpiresAt: persisted?.refreshExpiresAt ?? current?.refreshExpiresAt,
      issuedAt: current?.issuedAt ?? 0,
      authSession: persisted?.authSession ?? current?.authSession,
    };
    try {
      const refreshed = await this.tokens.refresh(base);
      await this.store(refreshed);
      return refreshed;
    } catch (e) {
      const error = NativeAuthError.from(e);
      if (error.code === NativeAuthErrorCode.invalidGrant) {
        // The session behind the refresh token is gone (logout, expiry, revocation).
        await this.clear();
        throw new NativeAuthError(NativeAuthErrorCode.reauthenticationRequired, error.errorDescription, {
          statusCode: error.statusCode,
          details: error.details,
          cause: error,
        });
      }
      throw error;
    }
  }

  private async read(): Promise<Persisted | undefined> {
    try {
      const value = await this.kv.get<Persisted>(this.key);
      return value?.refreshToken === undefined ? undefined : value;
    } catch (e) {
      this.warn(`Could not read stored credentials: ${String(e)}`);
      return undefined;
    }
  }

  private async persist(credentials: Credentials): Promise<void> {
    if (credentials.refreshToken === undefined) {
      await this.kv.remove(this.key).catch(() => {});
      return;
    }
    const record: Persisted = {
      refreshToken: credentials.refreshToken,
      refreshExpiresAt: credentials.refreshExpiresAt,
      tokenType: credentials.tokenType,
      scope: credentials.scope,
      authSession: credentials.authSession,
    };
    try {
      await this.kv.set(this.key, record);
    } catch (e) {
      this.warn(`Could not persist the session; a reload will sign the user out: ${String(e)}`);
    }
  }

  private async withLock<T>(body: () => Promise<T>): Promise<T> {
    const locks = typeof navigator === 'undefined' ? undefined : navigator.locks;
    if (locks === undefined) return body();
    return locks.request(`keycloak-web:refresh:${this.key}`, body);
  }

  private emit(): void {
    for (const listener of this.listeners) listener(this.current);
  }
}
