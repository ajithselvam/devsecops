"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRoutes = authRoutes;
const database_1 = require("../../shared/database");
const audit_1 = require("../../shared/utils/audit");
/**
 * Sign-up, sign-in, password reset and OAuth all live in InsForge auth and are
 * called by the browser through the SDK. The API only serves the authenticated
 * user's own profile and records the session events it needs to audit.
 */
async function authRoutes(app) {
    app.get('/me', {
        preHandler: [app.authenticate]
    }, async (request) => {
        const userId = request.user.userId;
        const user = await database_1.prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true, email: true, name: true, avatarUrl: true, role: true, theme: true,
                sidebarCollapsed: true, language: true, emailNotifications: true,
                inAppNotifications: true, notifyScanComplete: true, notifyScanFailed: true,
                notifyVulnFound: true, notifyJobChange: true, lastLoginAt: true, createdAt: true
            }
        });
        return { success: true, data: user };
    });
    app.patch('/me', {
        preHandler: [app.authenticate]
    }, async (request) => {
        const userId = request.user.userId;
        const { name, ...profile } = (request.body ?? {});
        // The display name is stored in public.profiles; auth.users.profile is
        // provider-owned metadata and only a user session may write it, so the
        // browser mirrors the change with `client.auth.setProfile()`.
        const data = name === undefined
            ? profile
            : { ...profile, name: name === null ? null : String(name) };
        const updated = Object.keys(data).length > 0
            ? await database_1.prisma.user.update({ where: { id: userId }, data })
            : await database_1.prisma.user.findUnique({ where: { id: userId } });
        await (0, audit_1.auditLog)(request, 'PROFILE_UPDATED', 'user', userId);
        return { success: true, data: updated };
    });
    app.post('/logout', {
        preHandler: [app.authenticate]
    }, async (request) => {
        await (0, audit_1.auditLog)(request, 'LOGOUT', 'user', request.user.userId);
        return { success: true, message: 'Logged out successfully' };
    });
}
