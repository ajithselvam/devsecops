"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scansRoutes = scansRoutes;
const database_1 = require("../../shared/database");
const audit_1 = require("../../shared/utils/audit");
const listSchema = {
    type: 'object',
    properties: {
        page: { type: 'number', default: 1 },
        pageSize: { type: 'number', default: 20 },
        type: { type: 'array', items: { type: 'string', enum: ['dockerfile', 'docker_image', 'kubernetes', 'jenkinsfile', 'github_repo', 'dependency', 'logs'] } },
        status: { type: 'array', items: { type: 'string', enum: ['pending', 'running', 'completed', 'failed', 'cancelled'] } },
        search: { type: 'string' },
        sortBy: { type: 'string', enum: ['createdAt', 'duration', 'severity'], default: 'createdAt' },
        sortOrder: { type: 'string', enum: ['asc', 'desc'], default: 'desc' }
    }
};
const batchDeleteSchema = {
    type: 'object',
    required: ['ids'],
    properties: {
        ids: { type: 'array', items: { type: 'string', format: 'uuid' }, minItems: 1 }
    }
};
const exportSchema = {
    type: 'object',
    properties: {
        format: { type: 'string', enum: ['json', 'csv'], default: 'json' },
        type: { type: 'array', items: { type: 'string', enum: ['dockerfile', 'docker_image', 'kubernetes', 'jenkinsfile', 'github_repo', 'dependency', 'logs'] } },
        status: { type: 'array', items: { type: 'string', enum: ['pending', 'running', 'completed', 'failed', 'cancelled'] } },
        search: { type: 'string' }
    }
};
async function scansRoutes(app) {
    // List scans with pagination and filters
    app.get('/', {
        preHandler: [app.authenticate],
        schema: { querystring: listSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { page, pageSize, type, status, search, sortBy, sortOrder } = request.query;
        const where = { userId };
        if (type?.length)
            where.type = { in: type };
        if (status?.length)
            where.status = { in: status };
        if (search) {
            where.OR = [
                { name: { contains: search, mode: 'insensitive' } },
                { targetValue: { contains: search, mode: 'insensitive' } },
                { id: { contains: search, mode: 'insensitive' } }
            ];
        }
        const [scans, total] = await Promise.all([
            database_1.prisma.scan.findMany({
                where,
                orderBy: { [sortBy]: sortOrder },
                take: pageSize,
                skip: (page - 1) * pageSize,
                include: {
                    findings: {
                        select: { severity: true },
                        where: { status: 'open' }
                    }
                }
            }),
            database_1.prisma.scan.count({ where })
        ]);
        const data = scans.map((scan) => ({
            ...scan,
            summary: {
                totalFindings: scan.findings?.length || 0,
                critical: scan.findings?.filter((f) => f.severity === 'critical').length || 0,
                high: scan.findings?.filter((f) => f.severity === 'high').length || 0,
                medium: scan.findings?.filter((f) => f.severity === 'medium').length || 0,
                low: scan.findings?.filter((f) => f.severity === 'low').length || 0,
                info: scan.findings?.filter((f) => f.severity === 'info').length || 0
            },
            duration: null // job relation removed
        }));
        return {
            success: true,
            data: {
                scans: data,
                total,
                totalPages: Math.ceil(total / pageSize),
                page,
                pageSize
            }
        };
    });
    // Get single scan with findings
    app.get('/:id', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const scan = await database_1.prisma.scan.findUnique({
            where: { id },
            include: {
                findings: { orderBy: [{ severity: 'desc' }, { createdAt: 'desc' }] }
            }
        });
        if (!scan || scan.userId !== userId) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 } });
        }
        return { success: true, data: scan };
    });
    // Delete scan
    app.delete('/:id', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const scan = await database_1.prisma.scan.findUnique({ where: { id } });
        if (!scan || scan.userId !== userId) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 } });
        }
        await database_1.prisma.scan.delete({ where: { id } });
        await (0, audit_1.auditLog)(request, 'SCAN_DELETED', 'scan', id);
        return { success: true, message: 'Scan deleted' };
    });
    // Batch delete
    app.delete('/batch', {
        preHandler: [app.authenticate],
        schema: { body: batchDeleteSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { ids } = request.body;
        const scans = await database_1.prisma.scan.findMany({
            where: { id: { in: ids }, userId },
            select: { id: true }
        });
        if (scans.length === 0) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'No scans found', statusCode: 404 } });
        }
        await database_1.prisma.scan.deleteMany({ where: { id: { in: ids }, userId } });
        await (0, audit_1.auditLog)(request, 'SCANS_BATCH_DELETED', 'scan', undefined, { count: scans.length, ids: scans.map(s => s.id) });
        return { success: true, message: `Deleted ${scans.length} scans`, data: { deleted: scans.length } };
    });
    // Export scans
    app.post('/export', {
        preHandler: [app.authenticate],
        schema: { body: exportSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { format, type, status, search } = request.body;
        const where = { userId };
        if (type?.length)
            where.type = { in: type };
        if (status?.length)
            where.status = { in: status };
        if (search) {
            where.OR = [
                { name: { contains: search, mode: 'insensitive' } },
                { targetValue: { contains: search, mode: 'insensitive' } },
                { id: { contains: search, mode: 'insensitive' } }
            ];
        }
        const scans = await database_1.prisma.scan.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            include: { findings: { select: { severity: true, type: true, title: true } } }
        });
        return { success: true, data: scans };
    });
    // Get scan stats
    app.get('/stats', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const [total, byType, byStatus, recent] = await Promise.all([
            database_1.prisma.scan.count({ where: { userId } }),
            database_1.prisma.scan.groupBy({ by: ['type'], where: { userId }, _count: true }),
            database_1.prisma.scan.groupBy({ by: ['status'], where: { userId }, _count: true }),
            database_1.prisma.scan.findMany({
                where: { userId },
                orderBy: { createdAt: 'desc' },
                take: 5,
                select: { id: true, targetValue: true, type: true, status: true, createdAt: true }
            })
        ]);
        return {
            success: true,
            data: {
                total,
                byType: byType.map(t => ({ type: t.type, count: t._count })),
                byStatus: byStatus.map(s => ({ status: s.status, count: s._count })),
                recent
            }
        };
    });
}
