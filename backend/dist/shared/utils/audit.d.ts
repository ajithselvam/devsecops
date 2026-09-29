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
export declare function auditLog(request: FastifyRequest, action: string, resource: string, resourceId?: string, metadata?: Record<string, any>): Promise<void>;
export declare function getAuditLogs(userId: string, options?: {
    page?: number;
    pageSize?: number;
    action?: string;
    resource?: string;
    startDate?: Date;
    endDate?: Date;
}): Promise<{
    logs: (import("../database/types").AuditLog & Pick<Record<string, unknown>, never>)[];
    total: number;
    totalPages: number;
    page: number;
    pageSize: number;
}>;
//# sourceMappingURL=audit.d.ts.map