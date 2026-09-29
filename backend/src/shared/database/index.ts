import { db } from './repository';

export { db };
export * from './insforge';
export * from './repository';

const globalForDb = globalThis as unknown as { db?: typeof db };
export const database = globalForDb.db ?? db;
if (process.env.NODE_ENV !== 'production') globalForDb.db = database;

/**
 * Prisma-flavoured alias kept so the 22 route modules that were written against
 * `prisma.<model>` keep compiling while the storage engine is InsForge.
 */
export const prisma = database;

// Helper functions for common operations
export async function createAuditLog(data: {
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  ip?: string;
  userAgent?: string;
}) {
  return database.auditLog.create({
    data: {
      ...data,
      metadata: data.metadata ? JSON.stringify(data.metadata) : null
    }
  });
}

export async function getUserWithSettings(userId: string) {
  return database.user.findUnique({
    where: { id: userId },
    include: { settings: true }
  });
}

export async function getUserSettings(userId: string) {
  return database.settings.findUnique({ where: { userId } });
}

export async function upsertUserSettings(userId: string, data: Record<string, unknown>) {
  return database.settings.upsert({
    where: { userId },
    create: { userId, ...data } as any,
    update: data
  });
}
