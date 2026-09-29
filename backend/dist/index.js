"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const fastify_1 = __importDefault(require("fastify"));
const cors_1 = require("@fastify/cors");
const helmet_1 = require("@fastify/helmet");
const multipart_1 = require("@fastify/multipart");
const rate_limit_1 = require("@fastify/rate-limit");
const websocket_1 = require("@fastify/websocket");
const config_1 = require("./shared/config");
const database_1 = require("./shared/database");
const routes_1 = require("./modules/routes");
const queue_1 = require("./shared/queue");
const websocket_2 = require("./shared/websocket");
const ai_1 = require("./shared/ai");
const logger_1 = require("./shared/utils/logger");
const auth_1 = require("./shared/utils/auth");
async function bootstrap() {
    const app = (0, fastify_1.default)({
        logger: config_1.config.NODE_ENV === 'development' ? {
            transport: {
                target: 'pino-pretty',
                options: { colorize: true, translateTime: 'HH:MM:ss Z', ignore: 'pid,hostname' }
            }
        } : true
    });
    // Security plugins
    await app.register(helmet_1.fastifyHelmet, {
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'https:'],
                connectSrc: ["'self'", 'ws:', 'wss:']
            }
        }
    });
    await app.register(cors_1.fastifyCors, {
        origin: config_1.config.CORS_ORIGIN,
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
    });
    await app.register(rate_limit_1.fastifyRateLimit, {
        max: config_1.config.RATE_LIMIT_MAX,
        timeWindow: config_1.config.RATE_LIMIT_WINDOW,
        keyGenerator: (req) => req.ip
    });
    // Auth plugin
    app.decorate('authenticate', async (request, reply) => {
        const claims = (0, auth_1.authenticateRequest)(request);
        if (!claims) {
            return reply.code(401).send({ success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid or expired token', statusCode: 401 } });
        }
        // public.profiles is provisioned by the on_auth_user_created trigger, so
        // there is no per-request work here.
        request.user = {
            userId: claims.sub,
            email: claims.email,
            role: claims.role ?? 'engineer'
        };
    });
    // Multipart for file uploads
    await app.register(multipart_1.fastifyMultipart, {
        limits: {
            fileSize: config_1.config.MAX_FILE_SIZE,
            files: 10
        }
    });
    // WebSocket for real-time updates
    await app.register(websocket_1.fastifyWebsocket);
    (0, websocket_2.initializeWebSocket)(app);
    // Health check
    app.get('/health', async () => ({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: config_1.config.APP_VERSION
    }));
    // Register all routes
    // Error handler
    app.setErrorHandler((error, request, reply) => {
        logger_1.logger.error({ err: error, url: request.url }, 'Request error');
        if (error.validation) {
            return reply.code(400).send({
                success: false,
                error: {
                    code: 'VALIDATION_ERROR',
                    message: 'Invalid request data',
                    details: error.validation,
                    statusCode: 400
                }
            });
        }
        // A path segment that is not a uuid means the client asked for a resource
        // that cannot exist, so report it as a 404 instead of leaking a 500.
        if (/invalid input syntax for type uuid|invalid UUID/i.test(error.message || '')) {
            return reply.code(404).send({
                success: false,
                error: {
                    code: 'NOT_FOUND',
                    message: 'Resource not found',
                    statusCode: 404
                }
            });
        }
        // Background jobs need Redis; without it these endpoints are unavailable
        // rather than broken.
        if (error.name === 'QueueUnavailableError') {
            return reply.code(503).send({
                success: false,
                error: {
                    code: 'QUEUE_UNAVAILABLE',
                    message: error.message,
                    statusCode: 503
                }
            });
        }
        const statusCode = error.statusCode || 500;
        reply.code(statusCode).send({
            success: false,
            error: {
                code: error.code || 'INTERNAL_ERROR',
                message: error.message || 'Internal server error',
                statusCode
            }
        });
    });
    // 404 handler
    app.setNotFoundHandler((request, reply) => {
        reply.code(404).send({
            success: false,
            error: { code: 'NOT_FOUND', message: `Route ${request.method} ${request.url} not found`, statusCode: 404 }
        });
    });
    await (0, routes_1.registerRoutes)(app);
    // Graceful shutdown
    const shutdown = async (signal) => {
        logger_1.logger.info({ signal }, 'Shutting down...');
        await (0, queue_1.shutdownQueue)();
        await app.close();
        await (0, database_1.closeDatabase)();
        process.exit(0);
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    try {
        // Initialize database
        await (0, database_1.initDatabase)();
        logger_1.logger.info('InsForge connected');
        // Initialize AI service
        await ai_1.aiService.initialize();
        logger_1.logger.info('AI service initialized');
        // Initialize job queue
        await (0, queue_1.initializeQueue)();
        logger_1.logger.info('Job queue initialized');
        // Start server
        await app.listen({ port: config_1.config.PORT, host: config_1.config.HOST });
        logger_1.logger.info(`Server running on http://${config_1.config.HOST}:${config_1.config.PORT}`);
    }
    catch (err) {
        logger_1.logger.error(err, 'Failed to start server');
        process.exit(1);
    }
}
bootstrap();
