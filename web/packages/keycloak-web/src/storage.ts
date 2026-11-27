import { NativeAuthError, NativeAuthErrorCode } from './errors';

/**
 * Where the SDK keeps what must survive a reload: the DPoP key pair (a non-extractable `CryptoKey`,
 * stored by structured clone) and the refresh token with the post-login `auth_session` (spec/22,
 * "Security model"). Values are anything IndexedDB can clone.
 */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T): Promise<void>;
  remove(key: string): Promise<void>;
}

/** Keeps everything in memory: a reload signs the user out. */
export class MemoryStore implements KeyValueStore {
  private readonly values = new Map<string, unknown>();

  async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  async set<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
  }

  async remove(key: string): Promise<void> {
    this.values.delete(key);
  }
}

/**
 * IndexedDB, one object store per database. Any failure (private mode, blocked site data, quota) is
 * a `storage_error`; `KeycloakWeb` then falls back to memory and logs a warning.
 */
export class IndexedDBStore implements KeyValueStore {
  private db: Promise<IDBDatabase> | undefined;

  constructor(
    private readonly databaseName = 'keycloak-web',
    private readonly storeName = 'state'
  ) {}

  static isAvailable(): boolean {
    try {
      return typeof indexedDB !== 'undefined' && indexedDB !== null;
    } catch {
      return false;
    }
  }

  async get<T>(key: string): Promise<T | undefined> {
    const value = await this.run<unknown>('readonly', (s) => s.get(key));
    return value as T | undefined;
  }

  async set<T>(key: string, value: T): Promise<void> {
    await this.run('readwrite', (s) => s.put(value, key));
  }

  async remove(key: string): Promise<void> {
    await this.run('readwrite', (s) => s.delete(key));
  }

  private open(): Promise<IDBDatabase> {
    if (this.db === undefined) {
      this.db = new Promise<IDBDatabase>((resolve, reject) => {
        let request: IDBOpenDBRequest;
        try {
          request = indexedDB.open(this.databaseName, 1);
        } catch (e) {
          reject(e);
          return;
        }
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(this.storeName)) {
            request.result.createObjectStore(this.storeName);
          }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        request.onblocked = () => reject(new Error('IndexedDB open blocked'));
      });
      this.db.catch(() => {
        this.db = undefined;
      });
    }
    return this.db;
  }

  private async run<T>(
    mode: IDBTransactionMode,
    body: (store: IDBObjectStore) => IDBRequest
  ): Promise<T> {
    try {
      const db = await this.open();
      return await new Promise<T>((resolve, reject) => {
        const tx = db.transaction(this.storeName, mode);
        const request = body(tx.objectStore(this.storeName));
        tx.oncomplete = () => resolve(request.result as T);
        tx.onerror = () => reject(tx.error ?? request.error);
        tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
      });
    } catch (e) {
      throw new NativeAuthError(
        NativeAuthErrorCode.storageError,
        `IndexedDB failed: ${e instanceof Error ? e.message : String(e)}`,
        { cause: e }
      );
    }
  }
}
