import { createClient } from '@insforge/sdk';
import { runtimeConfig } from './runtimeConfig';

const url = runtimeConfig.insforgeUrl;
const anonKey = runtimeConfig.insforgeAnonKey;

if (!url || !anonKey) {
  throw new Error(
    'Missing VITE_INSFORGE_URL / VITE_INSFORGE_ANON_KEY. Copy .env.example to .env and fill them in.'
  );
}

/**
 * Browser client. It only ever holds the anon key, which is public by design;
 * the admin API key stays on the server. Session tokens are persisted by the
 * SDK, so the app never touches localStorage for auth.
 */
export const insforge = createClient({
  baseUrl: url,
  anonKey,
  auth: {
    // The SDK would otherwise swap ?insforge_code= for an in-memory session of
    // its own. This app mirrors the session into localStorage (lib/session.ts)
    // and that token is not readable from outside the SDK, so the exchange runs
    // in lib/oauth.ts instead, where the access token can be persisted.
    detectOAuthCallback: false
  }
});

export type InsForgeClient = typeof insforge;
