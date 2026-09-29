import { config } from '../config';

type InsForgeSdk = typeof import('@insforge/sdk');
type AdminClient = ReturnType<InsForgeSdk['createAdminClient']>;

let sdkPromise: Promise<InsForgeSdk> | null = null;
let adminClient: AdminClient | null = null;

/**
 * `@insforge/sdk` ships a CommonJS entry that requires `@insforge/shared-schemas`,
 * which only declares an `import` export condition, so a plain `require()` throws
 * ERR_PACKAGE_PATH_NOT_EXPORTED. TypeScript keeps `import()` intact under
 * `module: NodeNext`, so loading the ESM build through a dynamic import is the
 * workaround. Reported upstream as feedback id b343f49c.
 */
function loadSdk(): Promise<InsForgeSdk> {
  if (!sdkPromise) {
    // The ESM namespace carries a `default` interop wrapper, so cast to the
    // published module type.
    sdkPromise = import('@insforge/sdk') as unknown as Promise<InsForgeSdk>;
  }
  return sdkPromise;
}

export async function initDatabase(): Promise<AdminClient> {
  if (adminClient) return adminClient;

  const sdk = await loadSdk();
  adminClient = sdk.createAdminClient({
    baseUrl: config.INSFORGE_URL,
    apiKey: config.INSFORGE_API_KEY
  });
  return adminClient;
}

/** Throws if called before `initDatabase()`; bootstrap awaits init first. */
export function getAdmin(): AdminClient {
  if (!adminClient) {
    throw new Error('InsForge admin client not initialised. Call initDatabase() during bootstrap.');
  }
  return adminClient;
}

export async function closeDatabase(): Promise<void> {
  adminClient = null;
  sdkPromise = null;
}

export function getStorageBucket(bucket: string) {
  return getAdmin().storage.from(bucket);
}

/**
 * Uploads a buffer to a private bucket.
 *
 * The storage RLS policies key the first path segment off the caller's JWT
 * `sub`, so every object must live under the owner's UUID.
 */
export async function uploadUserObject(
  bucket: string,
  userId: string,
  name: string,
  body: Buffer,
  contentType = 'application/octet-stream'
): Promise<string> {
  const path = userObjectPath(userId, name);
  const blob = new Blob([new Uint8Array(body)], { type: contentType });
  const result = await getStorageBucket(bucket).upload(path, blob);
  if (result.error) {
    throw new Error(`Storage upload failed for ${path}: ${result.error.message}`);
  }
  return path;
}

/** Short-lived download URL; the buckets are private, so objects are never public. */
export async function createUserObjectUrl(bucket: string, key: string, expiresIn = 900): Promise<string> {
  const result = await getStorageBucket(bucket).createSignedUrl(key, expiresIn);
  if (result.error || !result.data?.signedUrl) {
    throw new Error(`Could not sign ${key}: ${result.error?.message ?? 'no url returned'}`);
  }
  return result.data.signedUrl;
}

export async function removeUserObject(bucket: string, key: string): Promise<void> {
  const result = await getStorageBucket(bucket).remove(key);
  if (result.error) {
    throw new Error(`Storage delete failed for ${key}: ${result.error.message}`);
  }
}

/** Keeps the owner prefix and strips any path traversal from the file name. */
function userObjectPath(userId: string, name: string): string {
  const safe = name.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '_');
  return `${userId}/${Date.now()}-${safe}`;
}

export type { AdminClient };
