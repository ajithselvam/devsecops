"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditLog = auditLog;
exports.getAuditLogs = getAuditLogs;
const database_1 = require("../database");
async function auditLog(request, action, resource, resourceId, metadata) {
    try {
        const ip = request.ip || request.headers['x-forwarded-for'] || 'unknown';
        const userAgent = request.headers['user-agent'] || 'unknown';
        const userId = request.user?.userId || 'anonymous';
        await database_1.prisma.auditLog.create({
            data: {
                action,
                resource,
                resourceId,
                userId,
                metadata: metadata ? JSON.stringify(metadata) : null,
                ip,
                userAgent
            }
        });
    }
    catch (error) {
        // Don't fail the request if audit logging fails
        console.error('Audit log failed:', error);
    }
}
async function getAuditLogs(userId, options = {}) {
    const { page = 1, pageSize = 50, action, resource, startDate, endDate } = options;
    const where = { userId };
    if (action)
        where.action = action;
    if (resource)
        where.resource = resource;
    if (startDate || endDate) {
        where.createdAt = {};
        if (startDate)
            where.createdAt.gte = startDate;
        if (endDate)
            where.createdAt.lte = endDate;
    }
    const [logs, total] = await Promise.all([
        database_1.prisma.auditLog.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            take: pageSize,
            skip: (page - 1) * pageSize
        }),
        database_1.prisma.auditLog.count({ where })
    ]);
    return {
        logs,
        total,
        totalPages: Math.ceil(total / pageSize),
        page,
        pageSize
    };
}
