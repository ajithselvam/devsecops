"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jobsRoutes = jobsRoutes;
const database_1 = require("../../shared/database");
const audit_1 = require("../../shared/utils/audit");
const listSchema = {
    type: 'object',
    properties: {
        page: { type: 'number', default: 1 },
        pageSize: { type: 'number', default: 20 },
        status: { type: 'array', items: { type: 'string', enum: ['queued', 'running', 'analyzing', 'fixing', 'completed', 'failed', 'cancelled'] } },
        type: { type: 'array', items: { type: 'string' } }
    }
};
async function jobsRoutes(app) {
    // List jobs
    app.get('/', {
        preHandler: [app.authenticate],
        schema: { querystring: listSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { page, pageSize, status, type } = request.query;
        const where = { userId };
        if (status?.length)
            where.status = { in: status };
        if (type?.length)
            where.type = { in: type };
        const [jobs, total] = await Promise.all([
            database_1.prisma.job.findMany({
                where,
                orderBy: { createdAt: 'desc' },
                take: pageSize,
                skip: (page - 1) * pageSize
            }),
            database_1.prisma.job.count({ where })
        ]);
        return {
            success: true,
            data: {
                jobs,
                total,
                totalPages: Math.ceil(total / pageSize),
                page,
                pageSize
            }
        };
    });
    // Get job details
    app.get('/:id', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const job = await database_1.prisma.job.findUnique({
            where: { id }
        });
        if (!job || job.userId !== userId) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Job not found', statusCode: 404 } });
        }
        return { success: true, data: job };
    });
    // Cancel job
    app.post('/:id/cancel', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const job = await database_1.prisma.job.findUnique({ where: { id } });
        if (!job || job.userId !== userId) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Job not found', statusCode: 404 } });
        }
        if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
            return reply.code(400).send({ success: false, error: { code: 'INVALID_STATE', message: 'Cannot cancel completed job', statusCode: 400 } });
        }
        // In production, would cancel the BullMQ job
        await database_1.prisma.job.update({
            where: { id },
            data: { status: 'cancelled', completedAt: new Date(), error: 'Cancelled by user' }
        });
        await (0, audit_1.auditLog)(request, 'JOB_CANCELLED', 'job', id);
        return { success: true, message: 'Job cancelled' };
    });
    // Retry failed job
    app.post('/:id/retry', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const job = await database_1.prisma.job.findUnique({ where: { id } });
        if (!job || job.userId !== userId) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Job not found', statusCode: 404 } });
        }
        if (job.status !== 'failed') {
            return reply.code(400).send({ success: false, error: { code: 'INVALID_STATE', message: 'Can only retry failed jobs', statusCode: 400 } });
        }
        // Reset job status to queued
        await database_1.prisma.job.update({
            where: { id },
            data: { status: 'queued', progress: 0, error: null, startedAt: null, completedAt: null }
        });
        // In production, would re-queue the job
        await (0, audit_1.auditLog)(request, 'JOB_RETRIED', 'job', id);
        return { success: true, message: 'Job queued for retry' };
    });
    // Get job stats
    app.get('/stats', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const [total, byStatus, byType, running] = await Promise.all([
            database_1.prisma.job.count({ where: { userId } }),
            database_1.prisma.job.groupBy({ by: ['status'], where: { userId }, _count: true }),
            database_1.prisma.job.groupBy({ by: ['type'], where: { userId }, _count: true }),
            database_1.prisma.job.count({ where: { userId, status: { in: ['queued', 'running', 'analyzing', 'fixing'] } } })
        ]);
        return {
            success: true,
            data: {
                total,
                running,
                byStatus: byStatus.map(s => ({ status: s.status, count: s._count })),
                byType: byType.map(t => ({ type: t.type, count: t._count }))
            }
        };
    });
}
