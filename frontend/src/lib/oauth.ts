import { insforge } from './insforge';
import { rememberSession } from './session';
import { createPkcePair } from './pkce';

/**
 * OAuth sign-in, driving the InsForge endpoints directly.
 *
 * Two things the SDK's own `signInWithOAuth()` cannot do for this deployment:
 *
 *  - It builds the PKCE pair with `crypto.subtle`, which is undefined outside a
 *    secure context, so over plain HTTP on the k8s NodePort it throws and the
 *    SDK reports "An unexpected error occurred during OAuth initialization".
 *    The pair is generated here instead, with a SHA-256 fallback (lib/pkce.ts).
 *  - Its automatic callback handling (see `detectOAuthCallback` in
 *    lib/insforge.ts, disabled for this app) keeps the session in memory, and
 *    that token is not readable from outside the SDK. This app mirrors the
 *    session into localStorage so a reload does not sign the user out, so the
 *    code exchange runs here where the access token can be persisted.
 */

const VERIFIER_KEY = 'insforge_oauth_verifier';

export type OAuthProvider = 'google' | 'github';

/** InsForge built-in providers this project has configured. */
export const OAUTH_PROVIDERS: { id: OAuthProvider; label: string }[] = [
  { id: 'google', label: 'Google' },
  { id: 'github', label: 'GitHub' }
];

/**
 * Providers the backend serves from `/api/auth/oauth/<provider>` rather than
 * the `/custom/` path. Mirrors the SDK's built-in list.
 */
const BUILT_IN_PROVIDERS = [
  'google', 'github', 'discord', 'linkedin', 'facebook', 'instagram',
  'tiktok', 'apple', 'x', 'spotify', 'microsoft'
];

function readVerifier(): string | null {
  try {
    return sessionStorage.getItem(VERIFIER_KEY);
  } catch {
    return null;
  }
}

function writeVerifier(value: string): void {
  try {
    sessionStorage.setItem(VERIFIER_KEY, value);
  } catch {
    // Storage disabled; the exchange below then fails loudly instead of
    // silently leaving the user signed out.
  }
}

function clearVerifier(): void {
  try {
    sessionStorage.removeItem(VERIFIER_KEY);
  } catch {
    // ignore
  }
}

/**
 * Starts the redirect to the provider. Never resolves: the browser leaves the
 * page, and the session is picked up by `completeOAuthCallback()` on the way
 * back. `returnTo` is where InsForge sends the user, and it has to be on the
 * project's allowed redirect list.
 */
export async function startOAuth(provider: OAuthProvider, returnTo = '/'): Promise<never> {
  const { verifier, challenge } = await createPkcePair();
  const providerKey = provider.toLowerCase();
  const path = BUILT_IN_PROVIDERS.includes(providerKey)
    ? `/api/auth/oauth/${providerKey}`
    : `/api/auth/oauth/custom/${providerKey}`;

  let authUrl: string | undefined;
  try {
    // The HTTP client is the SDK's own, so the anon key and base URL stay in
    // one place; this is the same request signInWithOAuth() would have made.
    const response = await insforge.getHttpClient().get<{ authUrl?: string }>(path, {
      params: {
        redirect_uri: `${window.location.origin}${returnTo}`,
        code_challenge: challenge
      },
      skipAuthRefresh: true
    });
    authUrl = response?.authUrl;
  } catch (err: any) {
    throw new Error(err?.message || `Could not start ${provider} sign-in`);
  }

  if (!authUrl) {
    throw new Error(`Could not start ${provider} sign-in`);
  }

  writeVerifier(verifier);
  window.location.assign(authUrl);
  throw new Error('OAuth redirect started');
}

/**
 * Finishes a redirect that is already in the URL: exchanges the code, persists
 * the session, and cleans the query out of the address bar. Returns the path
 * the user landed on, or null when this is an ordinary page load.
 */
export async function completeOAuthCallback(): Promise<string | null> {
  const params = new URLSearchParams(window.location.search);
  const oauthError = params.get('error');
  const code = params.get('insforge_code');

  if (!oauthError && !code) return null;

  // Read the verifier before clearing it; the exchange below still needs it.
  const codeVerifier = readVerifier();
  clearVerifier();
  params.delete('error');
  params.delete('error_description');
  params.delete('insforge_code');
  const query = params.toString();
  window.history.replaceState(
    {},
    document.title,
    `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`
  );

  if (oauthError) {
    throw new Error(oauthError.replace(/_/g, ' '));
  }

  const { data, error } = await insforge.auth.exchangeOAuthCode(code as string, codeVerifier ?? undefined);
  if (error || !data?.accessToken) {
    throw new Error(error?.message || 'Sign-in could not be completed');
  }

  // Same persistence path as password sign-in, so a reload keeps the session.
  rememberSession(data.accessToken, data.refreshToken);
  return window.location.pathname;
}
