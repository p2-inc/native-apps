import { NativeAuthError, NativeAuthErrorCode } from './errors';
import type { NativeLoginFlow } from './flow';
import type { MetadataClient } from './metadata';
import type { RedirectToWebRequest } from './model';
import type { Credentials, Tokens } from './tokens';
import { encodeForm } from './transport';

/**
 * The browser half of `redirect_to_web` (spec/03 §3.4): open `url` and hand back the callback URL.
 * The user closing it surfaces as `web_fallback_cancelled`.
 */
export interface WebAuthenticationPresenter {
  authenticate(url: string, redirectUri: string): Promise<string>;
}

export const POPUP_MESSAGE_TYPE = 'keycloak-web:callback';

/**
 * Opens Keycloak's pages in a popup and waits for it to reach the `redirect_uri`, which must be on
 * this page's origin. It reads the popup's URL once it is same-origin again; a callback page that
 * calls `completeWebFallbackPopup()` also works when the pages are isolated from each other
 * (`Cross-Origin-Opener-Policy`). The popup opens synchronously in `prepare()` so the browser's popup
 * blocker sees the user's click.
 */
export class PopupPresenter implements WebAuthenticationPresenter {
  private prepared: Window | null | undefined;

  constructor(
    private readonly features = 'popup=yes,width=480,height=720',
    private readonly pollMs = 250
  ) {}

  /** Opens an empty popup now, inside the click handler; `authenticate` then navigates it. */
  prepare(): void {
    if (typeof window === 'undefined') return;
    this.prepared = window.open('about:blank', 'keycloak-web-fallback', this.features);
  }

  authenticate(url: string, redirectUri: string): Promise<string> {
    const popup =
      this.prepared ??
      (typeof window === 'undefined'
        ? null
        : window.open(url, 'keycloak-web-fallback', this.features));
    this.prepared = undefined;
    if (popup === null) {
      return Promise.reject(
        new NativeAuthError(
          NativeAuthErrorCode.webFallbackFailed,
          'The browser blocked the popup; allow popups for this site or use the redirect fallback'
        )
      );
    }
    try {
      if (popup.location.href !== url) popup.location.href = url;
    } catch {
      popup.location.href = url;
    }
    const expected = new URL(redirectUri, window.location.href);
    return new Promise<string>((resolve, reject) => {
      const finish = (result: { url?: string; error?: NativeAuthError }) => {
        clearInterval(timer);
        window.removeEventListener('message', onMessage);
        try {
          popup.close();
        } catch {
          // Already closed.
        }
        if (result.url !== undefined) resolve(result.url);
        else reject(result.error);
      };
      const onMessage = (event: MessageEvent) => {
        const data = event.data as { type?: string; url?: string } | undefined;
        if (event.origin !== window.location.origin || data?.type !== POPUP_MESSAGE_TYPE) return;
        if (typeof data.url === 'string') finish({ url: data.url });
      };
      window.addEventListener('message', onMessage);
      const timer = setInterval(() => {
        let href: string | undefined;
        try {
          href = popup.location.href;
        } catch {
          // Still on Keycloak's origin.
        }
        if (href !== undefined && href !== 'about:blank' && isCallback(href, expected)) {
          finish({ url: href });
          return;
        }
        if (popup.closed) {
          finish({
            error: new NativeAuthError(NativeAuthErrorCode.webFallbackCancelled, 'The sign-in window was closed'),
          });
        }
      }, this.pollMs);
    });
  }
}

function isCallback(href: string, expected: URL): boolean {
  try {
    const u = new URL(href);
    return u.origin === expected.origin && u.pathname === expected.pathname;
  } catch {
    return false;
  }
}

/**
 * Call on the page the popup lands on (the `redirect_uri`) when that page cannot be read by the
 * opener: it posts its URL to the opener and closes. Returns `false` when this page is not a popup.
 */
export function completeWebFallbackPopup(): boolean {
  if (typeof window === 'undefined' || window.opener === null || window.opener === undefined) return false;
  (window.opener as Window).postMessage(
    { type: POPUP_MESSAGE_TYPE, url: window.location.href },
    window.location.origin
  );
  window.close();
  return true;
}

/** What a full-page redirect keeps in `sessionStorage` until the page comes back. */
interface PendingRedirect {
  codeVerifier: string;
  state?: string;
  redirectUri: string;
  returnTo: string;
}

const PENDING_KEY = 'keycloak-web:pending-redirect';

/**
 * Completes a `redirect_to_web` step (spec/03 §3.4): opens the realm's authorization endpoint with
 * `client_id` + `request_uri`, checks `state` on the callback, and exchanges the code with the native
 * flow's PKCE verifier and the request's `redirect_uri`.
 */
export class WebFallback {
  constructor(
    private readonly clientId: string,
    private readonly issuer: string,
    private readonly metadata: MetadataClient,
    private readonly presenter: WebAuthenticationPresenter,
    private readonly tokens: Tokens
  ) {}

  /** The URL the browser is sent to. */
  async authorizationUrl(request: RedirectToWebRequest): Promise<string> {
    const endpoint =
      (await this.metadata.metadata()).authorizationEndpoint ??
      `${this.issuer}/protocol/openid-connect/auth`;
    const query = encodeForm([
      ['client_id', this.clientId],
      ['request_uri', request.requestUri],
    ]);
    return endpoint + (endpoint.includes('?') ? '&' : '?') + query;
  }

  /** Runs the popup and exchanges the code. */
  async complete(request: RedirectToWebRequest, flow: NativeLoginFlow): Promise<Credentials> {
    const url = await this.authorizationUrl(request);
    const callback = await this.presenter.authenticate(url, request.redirectUri);
    const code = callbackCode(callback, request.state);
    const credentials = await this.tokens.exchange(code, flow.pkce.verifier, {
      redirectUri: request.redirectUri,
    });
    flow.browserCompleted(callbackParam(callback, 'kc_action_status'));
    return credentials;
  }

  /**
   * Leaves the page for Keycloak (when popups are not an option). The page comes back to the
   * request's `redirect_uri`; call `KeycloakWeb.handleRedirectCallback()` there.
   */
  async redirect(request: RedirectToWebRequest, flow: NativeLoginFlow, returnTo = window.location.href): Promise<never> {
    const pending: PendingRedirect = {
      codeVerifier: flow.pkce.verifier,
      state: request.state,
      redirectUri: request.redirectUri,
      returnTo,
    };
    sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
    window.location.assign(await this.authorizationUrl(request));
    // The page is unloading.
    return new Promise<never>(() => {});
  }

  /**
   * After `redirect`: exchanges the code on the current URL. `undefined` when this page load is not
   * a fallback callback. The caller replaces the URL with `returnTo` afterwards.
   */
  async handleRedirectCallback(
    href = window.location.href
  ): Promise<{ credentials: Credentials; kcActionStatus?: string; returnTo: string } | undefined> {
    const raw = sessionStorage.getItem(PENDING_KEY);
    if (raw === null) return undefined;
    const pending = JSON.parse(raw) as PendingRedirect;
    const url = new URL(href);
    if (!url.searchParams.has('code') && !url.searchParams.has('error')) return undefined;
    sessionStorage.removeItem(PENDING_KEY);
    const code = callbackCode(href, pending.state);
    const credentials = await this.tokens.exchange(code, pending.codeVerifier, {
      redirectUri: pending.redirectUri,
    });
    const kcActionStatus = callbackParam(href, 'kc_action_status');
    return {
      credentials,
      ...(kcActionStatus !== undefined && { kcActionStatus }),
      returnTo: pending.returnTo,
    };
  }
}

function callbackParam(callback: string, name: string): string | undefined {
  const url = new URL(callback);
  const fromQuery = url.searchParams.get(name);
  if (fromQuery !== null) return fromQuery;
  return new URLSearchParams(url.hash.replace(/^#/, '')).get(name) ?? undefined;
}

/** Extracts `code`, enforcing `state` and surfacing an OAuth `error`. */
export function callbackCode(callback: string, expectedState: string | undefined): string {
  const error = callbackParam(callback, 'error');
  if (error !== undefined) {
    throw new NativeAuthError(error, callbackParam(callback, 'error_description') ?? 'The browser flow failed');
  }
  if (expectedState !== undefined && callbackParam(callback, 'state') !== expectedState) {
    throw new NativeAuthError(
      NativeAuthErrorCode.invalidResponse,
      'state on the callback does not match the redirect_to_web request'
    );
  }
  const code = callbackParam(callback, 'code');
  if (code === undefined || code.length === 0) {
    throw new NativeAuthError(NativeAuthErrorCode.invalidResponse, 'Callback without a code');
  }
  return code;
}
