import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import {
  defaultLoginStrings,
  idTokenClaims,
  type Credentials,
  type KeycloakWeb,
  type LoginStrings,
} from '@p2-inc/keycloak-web';

interface KeycloakContextValue {
  kc: KeycloakWeb;
  strings: LoginStrings;
  /** `true` until the stored session (if any) has been restored or found gone. */
  restoring: boolean;
}

const KeycloakContext = createContext<KeycloakContextValue | undefined>(undefined);

export interface KeycloakProviderProps {
  kc: KeycloakWeb;
  /** Replaces some or all default strings of the components below. */
  strings?: Partial<LoginStrings>;
  /** Called with the outcome of restoring the session on mount (`undefined`: nobody signed in). */
  onRestored?: (credentials: Credentials | undefined) => void;
  children: ReactNode;
}

/**
 * Makes a `KeycloakWeb` instance available to the hooks and components below, and restores the
 * stored session once on mount (also finishing a full-page browser fallback that returned here).
 */
export function KeycloakProvider({ kc, strings, onRestored, children }: KeycloakProviderProps) {
  const [restoring, setRestoring] = useState(true);
  useEffect(() => {
    let active = true;
    (async () => {
      let credentials: Credentials | undefined;
      try {
        const callback = await kc.handleRedirectCallback();
        if (callback !== undefined) {
          credentials = callback.credentials;
          window.history.replaceState(null, '', callback.returnTo);
        } else {
          credentials = await kc.restore();
        }
      } catch {
        credentials = undefined;
      }
      if (active) {
        setRestoring(false);
        onRestored?.(credentials);
      }
    })();
    return () => {
      active = false;
    };
    // Restore once per instance.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kc]);
  const value = useMemo<KeycloakContextValue>(
    () => ({ kc, strings: { ...defaultLoginStrings, ...strings }, restoring }),
    [kc, strings, restoring]
  );
  return <KeycloakContext.Provider value={value}>{children}</KeycloakContext.Provider>;
}

export function useKeycloakContext(): KeycloakContextValue {
  const value = useContext(KeycloakContext);
  if (value === undefined) throw new Error('Wrap the app in <KeycloakProvider kc={…}>');
  return value;
}

export interface KeycloakState {
  kc: KeycloakWeb;
  /** The signed-in user's credentials in memory; `undefined` when signed out or still restoring. */
  credentials: Credentials | undefined;
  isAuthenticated: boolean;
  /** `true` while the stored session is being restored on mount. */
  restoring: boolean;
  /** Unverified ID token claims of the signed-in user, for display. */
  user: Record<string, unknown> | undefined;
  signOut: () => Promise<void>;
}

/** The SDK instance and the signed-in state, re-rendering on sign-in, refresh and sign-out (all tabs). */
export function useKeycloak(): KeycloakState {
  const { kc, restoring } = useKeycloakContext();
  const manager = kc.credentialsManager();
  const credentials = useSyncExternalStore(
    useCallback((listener) => manager.subscribe(() => listener()), [manager]),
    () => manager.snapshot,
    () => undefined
  );
  const signOut = useCallback(() => kc.signOut(), [kc]);
  return {
    kc,
    credentials,
    isAuthenticated: credentials !== undefined,
    restoring,
    user: credentials === undefined ? undefined : idTokenClaims(credentials),
    signOut,
  };
}
