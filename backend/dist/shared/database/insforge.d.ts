type InsForgeSdk = typeof import('@insforge/sdk');
type AdminClient = ReturnType<InsForgeSdk['createAdminClient']>;
export declare function initDatabase(): Promise<AdminClient>;
/** Throws if called before `initDatabase()`; bootstrap awaits init first. */
export declare function getAdmin(): AdminClient;
export declare function closeDatabase(): Promise<void>;
export declare function getStorageBucket(bucket: string): import("@insforge/sdk").StorageBucket;
/**
 * Uploads a buffer to a private bucket.
 *
 * The storage RLS policies key the first path segment off the caller's JWT
 * `sub`, so every object must live under the owner's UUID.
 */
export declare function uploadUserObject(bucket: string, userId: string, name: string, body: Buffer, contentType?: string): Promise<string>;
/** Short-lived download URL; the buckets are private, so objects are never public. */
export declare function createUserObjectUrl(bucket: string, key: string, expiresIn?: number): Promise<string>;
export declare function removeUserObject(bucket: string, key: string): Promise<void>;
export type { AdminClient };
//# sourceMappingURL=insforge.d.ts.map