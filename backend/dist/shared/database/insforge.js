"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.initDatabase = initDatabase;
exports.getAdmin = getAdmin;
exports.closeDatabase = closeDatabase;
exports.getStorageBucket = getStorageBucket;
exports.uploadUserObject = uploadUserObject;
exports.createUserObjectUrl = createUserObjectUrl;
exports.removeUserObject = removeUserObject;
const config_1 = require("../config");
let sdkPromise = null;
let adminClient = null;
/**
 * `@insforge/sdk` ships a CommonJS entry that requires `@insforge/shared-schemas`,
 * which only declares an `import` export condition, so a plain `require()` throws
 * ERR_PACKAGE_PATH_NOT_EXPORTED. TypeScript keeps `import()` intact under
 * `module: NodeNext`, so loading the ESM build through a dynamic import is the
 * workaround. Reported upstream as feedback id b343f49c.
 */
function loadSdk() {
    if (!sdkPromise) {
        // The ESM namespace carries a `default` interop wrapper, so cast to the
        // published module type.
        sdkPromise = import('@insforge/sdk');
    }
    return sdkPromise;
}
async function initDatabase() {
    if (adminClient)
        return adminClient;
    const sdk = await loadSdk();
    adminClient = sdk.createAdminClient({
        baseUrl: config_1.config.INSFORGE_URL,
        apiKey: config_1.config.INSFORGE_API_KEY
    });
    return adminClient;
}
/** Throws if called before `initDatabase()`; bootstrap awaits init first. */
function getAdmin() {
    if (!adminClient) {
        throw new Error('InsForge admin client not initialised. Call initDatabase() during bootstrap.');
    }
    return adminClient;
}
async function closeDatabase() {
    adminClient = null;
    sdkPromise = null;
}
function getStorageBucket(bucket) {
    return getAdmin().storage.from(bucket);
}
/**
 * Uploads a buffer to a private bucket.
 *
 * The storage RLS policies key the first path segment off the caller's JWT
 * `sub`, so every object must live under the owner's UUID.
 */
async function uploadUserObject(bucket, userId, name, body, contentType = 'application/octet-stream') {
    const path = userObjectPath(userId, name);
    const blob = new Blob([new Uint8Array(body)], { type: contentType });
    const result = await getStorageBucket(bucket).upload(path, blob);
    if (result.error) {
        throw new Error(`Storage upload failed for ${path}: ${result.error.message}`);
    }
    return path;
}
/** Short-lived download URL; the buckets are private, so objects are never public. */
async function createUserObjectUrl(bucket, key, expiresIn = 900) {
    const result = await getStorageBucket(bucket).createSignedUrl(key, expiresIn);
    if (result.error || !result.data?.signedUrl) {
        throw new Error(`Could not sign ${key}: ${result.error?.message ?? 'no url returned'}`);
    }
    return result.data.signedUrl;
}
async function removeUserObject(bucket, key) {
    const result = await getStorageBucket(bucket).remove(key);
    if (result.error) {
        throw new Error(`Storage delete failed for ${key}: ${result.error.message}`);
    }
}
/** Keeps the owner prefix and strips any path traversal from the file name. */
function userObjectPath(userId, name) {
    const safe = name.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '_');
    return `${userId}/${Date.now()}-${safe}`;
}
