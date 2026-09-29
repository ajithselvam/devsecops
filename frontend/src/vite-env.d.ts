/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_INSFORGE_URL: string;
  readonly VITE_INSFORGE_ANON_KEY: string;
  readonly VITE_WS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface Window {
  /**
   * Written by /runtime-config.js. Empty in local dev, populated by
   * docker/entrypoint.sh in the container image.
   */
  __RUNTIME_CONFIG__?: Partial<ImportMetaEnv>;
}
