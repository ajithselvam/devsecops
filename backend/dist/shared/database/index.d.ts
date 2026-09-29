import { db } from './repository';
export { db };
export * from './insforge';
export * from './repository';
export declare const database: import("./repository").Database;
/**
 * Prisma-flavoured alias kept so the 22 route modules that were written against
 * `prisma.<model>` keep compiling while the storage engine is InsForge.
 */
export declare const prisma: import("./repository").Database;
export declare function createAuditLog(data: {
    userId?: string;
    action: string;
    resource: string;
    resourceId?: string;
    metadata?: Record<string, unknown>;
    ip?: string;
    userAgent?: string;
}): Promise<import("./types").AuditLog>;
export declare function getUserWithSettings(userId: string): Promise<(import("./types").User & Pick<{
    settings: import("./types").Settings;
}, "settings">) | null>;
export declare function getUserSettings(userId: string): Promise<(import("./types").Settings & Pick<Record<string, unknown>, never>) | null>;
export declare function upsertUserSettings(userId: string, data: Record<string, unknown>): Promise<import("./types").Settings>;
//# sourceMappingURL=index.d.ts.map