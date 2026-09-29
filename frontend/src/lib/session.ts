import { insforge } from './insforge';

/**
 * The browser SDK deliberately keeps its session in memory (it never touches
 * localStorage), so a page reload would otherwise sign the user out. This module
 * mirrors the session into localStorage and rehydrates the SDK on boot using the
 * SDK's own `setAccessToken` / `refreshSession`, so token handling stays inside
 * the SDK.
 */

const STORAGE_KEY = 'insforge_session';

export interface StoredSession {
  accessToken: string;
  refreshToken: string | null;
  /** Epoch ms after which the access token must be refreshed before use. */
  expiresAt: number;
}

function read(): StoredSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredSession;
    return parsed?.accessToken ? parsed : null;
  } catch {
    return null;
  }
}

function write(session: StoredSession): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Private mode or quota exceeded; the in-memory session still works.
  }
}

export function clearStoredSession(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

function expiryOf(accessToken: string): number {
  try {
    const payload = JSON.parse(atob(accessToken.split('.')[1])) as { exp?: number };
    return payload.exp ? payload.exp * 1000 : Date.now() + 5 * 60_000;
  } catch {
    return Date.now() + 5 * 60_000;
  }
}

function persist(accessToken: string, refreshToken: string | null): StoredSession {
  const session: StoredSession = { accessToken, refreshToken, expiresAt: expiryOf(accessToken) };
  write(session);
  return session;
}

/** Call after any SDK call that returns a session. */
export function rememberSession(accessToken: string, refreshToken: string | null = null): void {
  persist(accessToken, refreshToken);
}

/**
 * Restores the session on boot. Returns the usable access token, refreshing it
 * first when it has expired.
 */
export async function restoreSession(): Promise<string | null> {
  const stored = read();
  if (!stored) return null;

  if (Date.now() < stored.expiresAt - 30_000) {
    insforge.setAccessToken(stored.accessToken);
    return stored.accessToken;
  }

  if (!stored.refreshToken) {
    clearStoredSession();
    return null;
  }

  const { data, error } = await insforge.auth.refreshSession({ refreshToken: stored.refreshToken });
  if (error || !data?.accessToken) {
    clearStoredSession();
    insforge.setAccessToken(null);
    return null;
  }

  const session = persist(data.accessToken, data.refreshToken ?? stored.refreshToken);
  insforge.setAccessToken(session.accessToken);
  return session.accessToken;
}

export function currentAccessToken(): string | null {
  return read()?.accessToken ?? null;
}
