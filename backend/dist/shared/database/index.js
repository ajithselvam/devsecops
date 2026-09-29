"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.prisma = exports.database = exports.db = void 0;
exports.createAuditLog = createAuditLog;
exports.getUserWithSettings = getUserWithSettings;
exports.getUserSettings = getUserSettings;
exports.upsertUserSettings = upsertUserSettings;
const repository_1 = require("./repository");
Object.defineProperty(exports, "db", { enumerable: true, get: function () { return repository_1.db; } });
__exportStar(require("./insforge"), exports);
__exportStar(require("./repository"), exports);
const globalForDb = globalThis;
exports.database = globalForDb.db ?? repository_1.db;
if (process.env.NODE_ENV !== 'production')
    globalForDb.db = exports.database;
/**
 * Prisma-flavoured alias kept so the 22 route modules that were written against
 * `prisma.<model>` keep compiling while the storage engine is InsForge.
 */
exports.prisma = exports.database;
// Helper functions for common operations
async function createAuditLog(data) {
    return exports.database.auditLog.create({
        data: {
            ...data,
            metadata: data.metadata ? JSON.stringify(data.metadata) : null
        }
    });
}
async function getUserWithSettings(userId) {
    return exports.database.user.findUnique({
        where: { id: userId },
        include: { settings: true }
    });
}
async function getUserSettings(userId) {
    return exports.database.settings.findUnique({ where: { userId } });
}
async function upsertUserSettings(userId, data) {
    return exports.database.settings.upsert({
        where: { userId },
        create: { userId, ...data },
        update: data
    });
}
