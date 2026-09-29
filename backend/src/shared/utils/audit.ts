import { prisma } from '../database';
import { FastifyRequest } from 'fastify';

export interface AuditLogEntry {
  action: string;
  resource: string;
  resourceId?: string;
  userId: string;
  metadata?: Record<string, any>;
  ip?: string;
  userAgent?: string;
}

export async function auditLog(
  request: FastifyRequest,
  action: string,
  resource: string,
  resourceId?: string,
  metadata?: Record<string, any>
): Promise<void> {
  try {
    const ip = request.ip || request.headers['x-forwarded-for'] as string || 'unknown';
    const userAgent = request.headers['user-agent'] || 'unknown';
    const userId = (request as any).user?.userId || 'anonymous';

    await prisma.auditLog.create({
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
  } catch (error) {
    // Don't fail the request if audit logging fails
    console.error('Audit log failed:', error);
  }
}

export async function getAuditLogs(
  userId: string,
  options: {
    page?: number;
    pageSize?: number;
    action?: string;
    resource?: string;
    startDate?: Date;
    endDate?: Date;
  } = {}
) {
  const { page = 1, pageSize = 50, action, resource, startDate, endDate } = options;

  const where: any = { userId };
  if (action) where.action = action;
  if (resource) where.resource = resource;
  if (startDate || endDate) {
    where.createdAt = {};
    if (startDate) where.createdAt.gte = startDate;
    if (endDate) where.createdAt.lte = endDate;
  }

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: pageSize,
      skip: (page - 1) * pageSize
    }),
    prisma.auditLog.count({ where })
  ]);

  return {
    logs,
    total,
    totalPages: Math.ceil(total / pageSize),
    page,
    pageSize
  };
}