import { sha256 } from './sha256';

/**
 * PKCE pair generation that works outside a secure context.
 *
 * The InsForge SDK builds its PKCE pair with `crypto.subtle`, which browsers
 * only expose over HTTPS or on localhost. The k8s deployment serves the app
 * over plain HTTP on a non-localhost host, so `subtle` is undefined and the
 * SDK fails with "An unexpected error occurred during OAuth initialization".
 * `crypto.getRandomValues` is not gated on a secure context, so only the
 * SHA-256 digest needs a fallback (lib/sha256.ts).
 */

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hasSubtleCrypto(): boolean {
  return typeof globalThis.crypto?.subtle?.digest === 'function';
}

async function digestBase64Url(message: Uint8Array): Promise<string> {
  if (hasSubtleCrypto()) {
    // Copied into a fresh buffer: SubtleCrypto.digest wants a view over a
    // plain ArrayBuffer, and a Uint8Array's buffer type is not narrowed to one.
    const hash = await globalThis.crypto.subtle.digest('SHA-256', Uint8Array.from(message));
    return base64Url(new Uint8Array(hash));
  }
  return base64Url(sha256(message));
}

/**
 * Returns a PKCE verifier and its S256 challenge. The verifier is 32 random
 * bytes, base64url-encoded to 43 characters, which is the RFC 7636 minimum.
 */
export async function createPkcePair(): Promise<{ verifier: string; challenge: string }> {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  const verifier = base64Url(bytes);
  const challenge = await digestBase64Url(new TextEncoder().encode(verifier));
  return { verifier, challenge };
}
