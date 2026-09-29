/**
 * Config that differs per environment.
 *
 * Inside the container image the values come from window.__RUNTIME_CONFIG__,
 * which docker/entrypoint.sh generates from the environment at start-up. That
 * keeps one image usable in every environment instead of baking the values
 * into the Vite bundle at build time. Locally (and in CI for static hosts) the
 * object is absent and the build-time VITE_* variables are used instead.
 */
const runtime = (typeof window !== 'undefined' && window.__RUNTIME_CONFIG__) || {};

export const runtimeConfig = {
  insforgeUrl: runtime.VITE_INSFORGE_URL || import.meta.env.VITE_INSFORGE_URL,
  insforgeAnonKey: runtime.VITE_INSFORGE_ANON_KEY || import.meta.env.VITE_INSFORGE_ANON_KEY,
  /** Empty means "same origin as the page", which is what the image serves. */
  wsUrl: runtime.VITE_WS_URL || import.meta.env.VITE_WS_URL || '',
};

/**
 * WebSocket origin for the current page. The API and the SPA are served from
 * the same nginx in the image, so the default has to follow the page origin
 * (including the NodePort and the http/https scheme) instead of a host baked
 * in at build time.
 */
export function websocketOrigin(): string {
  if (runtimeConfig.wsUrl) return runtimeConfig.wsUrl.replace(/\/$/, '');
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}`;
}
