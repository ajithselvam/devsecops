"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logsRoutes = logsRoutes;
const zlib_1 = require("zlib");
const database_1 = require("../../shared/database");
const insforge_1 = require("../../shared/database/insforge");
const config_1 = require("../../shared/config");
const logger_1 = require("../../shared/utils/logger");
const audit_1 = require("../../shared/utils/audit");
const ai_1 = require("../../shared/ai");
const searchSchema = {
    type: 'object',
    properties: {
        query: { type: 'string' },
        logFileIds: { type: 'array', items: { type: 'string' } },
        timeRange: {
            type: 'object',
            properties: {
                start: { type: 'string' },
                end: { type: 'string' }
            }
        },
        levels: { type: 'array', items: { type: 'string' } },
        level: { type: 'array', items: { type: 'string' } },
        services: { type: 'array', items: { type: 'string' } },
        service: { type: 'array', items: { type: 'string' } },
        limit: { type: 'number', default: 100 },
        offset: { type: 'number', default: 0 }
    }
};
const investigateSchema = {
    type: 'object',
    required: ['question', 'logFileIds'],
    properties: {
        question: { type: 'string', minLength: 1 },
        logFileIds: { type: 'array', items: { type: 'string' }, minItems: 1 },
        timeRange: {
            type: 'object',
            properties: {
                start: { type: 'string' },
                end: { type: 'string' }
            }
        }
    }
};
function parseAiJson(text) {
    let cleaned = (text || '').trim();
    cleaned = cleaned.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start >= 0 && end > start)
        cleaned = cleaned.slice(start, end + 1);
    return JSON.parse(cleaned);
}
function parseTimestamp(value) {
    if (!value)
        return new Date();
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? new Date() : d;
}
function normalizeLevel(raw) {
    const s = (raw || 'info').toLowerCase();
    if (['fatal', 'crit', 'critical', 'emerg', 'panic'].includes(s))
        return 'fatal';
    if (['error', 'err', 'severe'].includes(s))
        return 'error';
    if (['warn', 'warning'].includes(s))
        return 'warn';
    if (['debug'].includes(s))
        return 'debug';
    if (['trace', 'verbose'].includes(s))
        return 'trace';
    if (['info', 'information', 'notice'].includes(s))
        return 'info';
    return 'info';
}
function detectLevelFromLine(line) {
    const l = line.toLowerCase();
    if (/\b(fatal|panic|emerg)\b/.test(l))
        return 'fatal';
    if (/\b(error|exception|fail(ed|ure)?)\b/.test(l))
        return 'error';
    if (/\b(warn|warning)\b/.test(l))
        return 'warn';
    if (/\bdebug\b/.test(l))
        return 'debug';
    if (/\btrace\b/.test(l))
        return 'trace';
    return 'info';
}
function parseLogLine(line) {
    const trimmed = line.trim();
    try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === 'object') {
            return {
                timestamp: parseTimestamp(parsed.timestamp || parsed.time || parsed.ts || parsed['@timestamp']),
                level: normalizeLevel(parsed.level || parsed.severity || parsed.priority),
                service: String(parsed.service || parsed.component || parsed.logger || parsed.app || 'unknown'),
                message: String(parsed.message || parsed.msg || parsed.log || trimmed),
                fields: parsed
            };
        }
    }
    catch {
        // not JSON
    }
    const syslog = trimmed.match(/^(\w{3}\s+\d{1,2}\s[\d:]{8})\s+(\S+)\s+([^\s:]+)(?:\[\d+\])?:\s*(.*)$/);
    if (syslog) {
        return {
            timestamp: parseTimestamp(`${syslog[1]} ${new Date().getFullYear()}`),
            level: detectLevelFromLine(trimmed),
            service: syslog[3],
            message: syslog[4] || trimmed,
            fields: { host: syslog[2] }
        };
    }
    const iso = trimmed.match(/^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\w+)\s+(.*)$/);
    if (iso) {
        return {
            timestamp: parseTimestamp(iso[1]),
            level: normalizeLevel(iso[2]),
            service: 'unknown',
            message: iso[3],
            fields: {}
        };
    }
    return {
        timestamp: new Date(),
        level: detectLevelFromLine(trimmed),
        service: 'unknown',
        message: trimmed,
        fields: {}
    };
}
function serializeLogFile(file, services = []) {
    return {
        id: file.id,
        name: file.name,
        size: typeof file.size === 'bigint' ? Number(file.size) : Number(file.size || 0),
        lineCount: file.lineCount,
        format: file.format,
        indexed: file.indexed,
        uploadedAt: file.createdAt,
        createdAt: file.createdAt,
        userId: file.userId,
        services
    };
}
function serializeEntry(entry) {
    let fields = {};
    try {
        fields = typeof entry.fields === 'string' ? JSON.parse(entry.fields || '{}') : (entry.fields || {});
    }
    catch {
        fields = {};
    }
    return {
        id: entry.id,
        logFileId: entry.logFileId,
        timestamp: entry.timestamp instanceof Date ? entry.timestamp.toISOString() : String(entry.timestamp),
        level: entry.level,
        service: entry.service,
        message: entry.message,
        raw: entry.raw,
        fields,
        indexed: entry.indexed
    };
}
function heuristicInvestigation(question, entries) {
    const errorLike = entries.filter(e => ['error', 'fatal'].includes(e.level) || /error|exception|fail|timeout|refused/i.test(e.message));
    const services = [...new Set(entries.map(e => e.service).filter((s) => s && s !== 'unknown'))];
    const patternMap = new Map();
    for (const e of entries) {
        const key = e.message.replace(/\d+/g, 'N').slice(0, 120);
        const existing = patternMap.get(key);
        const ts = e.timestamp;
        if (!existing) {
            patternMap.set(key, { count: 1, firstSeen: ts, lastSeen: ts, examples: [e] });
        }
        else {
            existing.count += 1;
            existing.lastSeen = ts;
            if (existing.examples.length < 3)
                existing.examples.push(e);
        }
    }
    const errorPatterns = [...patternMap.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 8)
        .map(([pattern, info]) => ({
        pattern,
        count: info.count,
        firstSeen: info.firstSeen,
        lastSeen: info.lastSeen,
        examples: info.examples
    }));
    const timeline = errorLike.slice(0, 20).map(e => ({
        timestamp: e.timestamp,
        event: e.message.slice(0, 180),
        service: e.service,
        severity: e.level,
        entries: [e]
    }));
    const top = errorPatterns[0];
    const rootCause = errorLike.length
        ? `Detected ${errorLike.length} error-level events across ${services.length || 1} service(s). Dominant pattern: ${top?.pattern || 'unclassified errors'}. Question: "${question}"`
        : `No high-severity errors matched. Analyzed ${entries.length} entries for: "${question}"`;
    return {
        question,
        rootCause,
        evidence: errorLike.slice(0, 10).map(entry => ({
            entry,
            relevance: entry.level === 'fatal' ? 95 : entry.level === 'error' ? 85 : 60,
            explanation: `${entry.level.toUpperCase()} in ${entry.service}: ${entry.message.slice(0, 160)}`
        })),
        timeline,
        affectedServices: services.length ? services : ['unknown'],
        errorPatterns,
        recommendedActions: [
            'Inspect the most frequent error pattern and matching stack traces',
            'Check recent deploys, config changes, and dependency upgrades',
            'Verify downstream service health (database, cache, APIs)',
            'Add alerts for the top error signatures'
        ],
        confidence: errorLike.length ? 72 : 45,
        analyzedEntries: entries.length,
        analysisTime: new Date().toISOString()
    };
}
async function serializeFileWithServices(file) {
    const grouped = await database_1.prisma.logEntry.groupBy({
        by: ['service'],
        where: { logFileId: file.id }
    }).catch(() => []);
    const services = grouped.map(g => g.service).filter((s) => !!s);
    return serializeLogFile(file, services);
}
async function logsRoutes(app) {
    app.post('/upload', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const data = await request.file();
        if (!data) {
            return reply.code(400).send({
                success: false,
                error: { code: 'NO_FILE', message: 'No file uploaded', statusCode: 400 }
            });
        }
        const chunks = [];
        for await (const chunk of data.file)
            chunks.push(chunk);
        let buffer = Buffer.concat(chunks);
        try {
            if (data.filename.endsWith('.gz'))
                buffer = (0, zlib_1.gunzipSync)(buffer);
        }
        catch {
            return reply.code(400).send({
                success: false,
                error: { code: 'INVALID_GZIP', message: 'Could not decompress .gz log file', statusCode: 400 }
            });
        }
        const content = buffer.toString('utf-8');
        const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
        const format = data.filename.endsWith('.json') || lines.slice(0, 5).every(l => l.trim().startsWith('{'))
            ? 'json'
            : 'text';
        const logFile = await database_1.prisma.logFile.create({
            data: {
                name: data.filename.replace(/\.gz$/i, ''),
                size: BigInt(buffer.length),
                lineCount: lines.length,
                format,
                userId
            }
        });
        // Keep the original file in the private bucket. The first path segment must
        // be the owner's UUID to satisfy the storage RLS policy.
        let storageKey = null;
        try {
            storageKey = await (0, insforge_1.uploadUserObject)(config_1.config.INSFORGE_LOG_BUCKET, userId, logFile.name, buffer, format === 'json' ? 'application/json' : 'text/plain');
        }
        catch (error) {
            // The parsed entries are already stored, so a storage failure must not
            // discard the upload.
            logger_1.logger.error({ err: error, logFileId: logFile.id }, 'Failed to store uploaded log file');
        }
        const entries = lines.slice(0, 15000).map((line) => {
            const parsed = parseLogLine(line);
            return {
                logFileId: logFile.id,
                timestamp: parsed.timestamp,
                level: parsed.level,
                service: parsed.service,
                message: parsed.message.slice(0, 8000),
                raw: line.slice(0, 8000),
                fields: JSON.stringify(parsed.fields || {})
            };
        });
        if (entries.length > 0) {
            const chunkSize = 500;
            for (let i = 0; i < entries.length; i += chunkSize) {
                await database_1.prisma.logEntry.createMany({ data: entries.slice(i, i + chunkSize) });
            }
        }
        await database_1.prisma.logFile.update({
            where: { id: logFile.id },
            data: { indexed: true, storageKey }
        });
        await (0, audit_1.auditLog)(request, 'LOG_UPLOADED', 'log_file', logFile.id, { name: data.filename, lines: lines.length });
        const payload = await serializeFileWithServices(logFile);
        return { success: true, data: payload };
    });
    const listFiles = async (request) => {
        const userId = request.user.userId;
        const files = await database_1.prisma.logFile.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' }
        });
        const data = await Promise.all(files.map(serializeFileWithServices));
        return { success: true, data };
    };
    app.get('/', { preHandler: [app.authenticate] }, listFiles);
    app.get('/files', { preHandler: [app.authenticate] }, listFiles);
    const deleteFile = async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const logFile = await database_1.prisma.logFile.findUnique({ where: { id } });
        if (!logFile || logFile.userId !== userId) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Log file not found', statusCode: 404 }
            });
        }
        if (logFile.storageKey) {
            try {
                await (0, insforge_1.removeUserObject)(config_1.config.INSFORGE_LOG_BUCKET, logFile.storageKey);
            }
            catch (error) {
                logger_1.logger.error({ err: error, logFileId: id }, 'Failed to remove stored log file');
            }
        }
        await database_1.prisma.logFile.delete({ where: { id } });
        await (0, audit_1.auditLog)(request, 'LOG_DELETED', 'log_file', id);
        return { success: true, message: 'Log file deleted' };
    };
    app.delete('/files/:id', { preHandler: [app.authenticate] }, deleteFile);
    app.delete('/:id', { preHandler: [app.authenticate] }, deleteFile);
    // The bucket is private, so downloads are handed out as short-lived URLs.
    app.get('/:id/download', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const logFile = await database_1.prisma.logFile.findUnique({ where: { id } });
        if (!logFile || logFile.userId !== userId) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Log file not found', statusCode: 404 }
            });
        }
        if (!logFile.storageKey) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NO_FILE', message: 'Original file is no longer stored', statusCode: 404 }
            });
        }
        try {
            const url = await (0, insforge_1.createUserObjectUrl)(config_1.config.INSFORGE_LOG_BUCKET, logFile.storageKey);
            return { success: true, data: { url, name: logFile.name, expiresIn: 900 } };
        }
        catch (error) {
            logger_1.logger.error({ err: error, logFileId: id }, 'Failed to sign log file');
            return reply.code(500).send({
                success: false,
                error: { code: 'STORAGE_ERROR', message: 'Could not create a download link', statusCode: 500 }
            });
        }
    });
    app.get('/:id/entries', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const { limit, offset, level } = request.query || {};
        const logFile = await database_1.prisma.logFile.findUnique({ where: { id } });
        if (!logFile || logFile.userId !== userId) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Log file not found', statusCode: 404 }
            });
        }
        const where = { logFileId: id };
        if (level)
            where.level = level;
        const entries = await database_1.prisma.logEntry.findMany({
            where,
            orderBy: { timestamp: 'desc' },
            take: Number(limit) || 200,
            skip: Number(offset) || 0
        });
        return { success: true, data: entries.map(serializeEntry) };
    });
    app.post('/search', {
        preHandler: [app.authenticate],
        schema: { body: searchSchema }
    }, async (request) => {
        const userId = request.user.userId;
        const body = request.body;
        const userFiles = await database_1.prisma.logFile.findMany({ where: { userId }, select: { id: true } });
        const userFileIds = userFiles.map(f => f.id);
        const targetFileIds = body.logFileIds?.length
            ? body.logFileIds.filter(id => userFileIds.includes(id))
            : userFileIds;
        if (targetFileIds.length === 0) {
            return { success: true, data: { entries: [], total: 0, facets: { levels: {}, services: {}, timeDistribution: [] } } };
        }
        const levels = body.levels?.length ? body.levels : body.level;
        const services = body.services?.length ? body.services : body.service;
        const where = { logFileId: { in: targetFileIds } };
        if (body.query?.trim()) {
            // SQLite: LIKE is case-insensitive for ASCII; do not use Prisma `mode: insensitive`
            where.message = { contains: body.query.trim() };
        }
        if (body.timeRange?.start && body.timeRange?.end) {
            where.timestamp = { gte: new Date(body.timeRange.start), lte: new Date(body.timeRange.end) };
        }
        if (levels?.length)
            where.level = { in: levels };
        if (services?.length)
            where.service = { in: services };
        const take = Math.min(body.limit || 100, 500);
        const [entries, total] = await Promise.all([
            database_1.prisma.logEntry.findMany({
                where,
                orderBy: { timestamp: 'desc' },
                take,
                skip: body.offset || 0
            }),
            database_1.prisma.logEntry.count({ where })
        ]);
        return {
            success: true,
            data: {
                entries: entries.map(serializeEntry),
                total,
                facets: { levels: {}, services: {}, timeDistribution: [] }
            }
        };
    });
    app.post('/investigate', {
        preHandler: [app.authenticate],
        schema: { body: investigateSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { question, logFileIds, timeRange } = request.body;
        const files = await database_1.prisma.logFile.findMany({
            where: { id: { in: logFileIds }, userId }
        });
        if (files.length !== logFileIds.length) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Log files not found', statusCode: 404 }
            });
        }
        const where = { logFileId: { in: logFileIds } };
        if (timeRange?.start && timeRange?.end) {
            where.timestamp = { gte: new Date(timeRange.start), lte: new Date(timeRange.end) };
        }
        const rawEntries = await database_1.prisma.logEntry.findMany({
            where,
            orderBy: { timestamp: 'desc' },
            take: 1500
        });
        const entries = rawEntries.map(serializeEntry);
        const heuristic = heuristicInvestigation(question, entries);
        try {
            const ai = await ai_1.aiService.investigateLogs(question, entries.slice(0, 80).map(e => ({
                timestamp: e.timestamp,
                level: e.level,
                service: e.service,
                message: e.message
            })), { fileCount: files.length, totalEntries: entries.length });
            const result = {
                question,
                rootCause: ai.rootCause || heuristic.rootCause,
                evidence: (ai.evidence?.length ? ai.evidence : heuristic.evidence),
                timeline: (ai.timeline?.length ? ai.timeline : heuristic.timeline).map((t) => ({
                    timestamp: t.timestamp || new Date().toISOString(),
                    event: t.event || t.description || 'Event',
                    service: t.service,
                    severity: t.severity || 'info',
                    entries: t.entries || []
                })),
                affectedServices: ai.affectedServices?.length ? ai.affectedServices : heuristic.affectedServices,
                errorPatterns: (ai.errorPatterns?.length ? ai.errorPatterns : heuristic.errorPatterns).map((p) => ({
                    pattern: p.pattern || p.description || 'pattern',
                    count: p.count || 1,
                    firstSeen: p.firstSeen || entries[entries.length - 1]?.timestamp || new Date().toISOString(),
                    lastSeen: p.lastSeen || entries[0]?.timestamp || new Date().toISOString(),
                    examples: p.examples || []
                })),
                recommendedActions: ai.recommendedActions?.length ? ai.recommendedActions : heuristic.recommendedActions,
                confidence: typeof ai.confidence === 'number' ? ai.confidence : heuristic.confidence,
                analyzedEntries: ai.analyzedEntries || heuristic.analyzedEntries,
                analysisTime: new Date().toISOString()
            };
            await (0, audit_1.auditLog)(request, 'LOG_INVESTIGATION_COMPLETED', 'log_file', logFileIds[0], { question });
            return { success: true, data: result };
        }
        catch (error) {
            console.warn('AI log investigation fallback:', error?.message);
            await (0, audit_1.auditLog)(request, 'LOG_INVESTIGATION_COMPLETED', 'log_file', logFileIds[0], { question, fallback: true });
            return { success: true, data: heuristic };
        }
    });
}
