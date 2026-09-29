import 'dotenv/config';
import Fastify from 'fastify';
import { fastifyCors } from '@fastify/cors';
import { fastifyHelmet } from '@fastify/helmet';
import { fastifyMultipart } from '@fastify/multipart';
import { fastifyRateLimit } from '@fastify/rate-limit';
import { fastifyWebsocket } from '@fastify/websocket';
import pino from 'pino';

import { config } from './shared/config';
import { initDatabase, closeDatabase } from './shared/database';
import { registerRoutes } from './modules/routes';
import { initializeQueue, shutdownQueue } from './shared/queue';
import { initializeWebSocket } from './shared/websocket';
import { aiService } from './shared/ai';
import { logger } from './shared/utils/logger';
import { authenticateRequest } from './shared/utils/auth';

async function bootstrap() {
  const app = Fastify({
    logger: config.NODE_ENV === 'development' ? {
      transport: {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'HH:MM:ss Z', ignore: 'pid,hostname' }
      }
    } : true
  });

  // Security plugins
  await app.register(fastifyHelmet, {
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

  await app.register(fastifyCors, {
    origin: config.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
  });

  await app.register(fastifyRateLimit, {
    max: config.RATE_LIMIT_MAX,
    timeWindow: config.RATE_LIMIT_WINDOW,
    keyGenerator: (req) => req.ip
  });

  // Auth plugin
  app.decorate('authenticate', async (request: any, reply: any) => {
    const claims = authenticateRequest(request);
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
  await app.register(fastifyMultipart, {
    limits: {
      fileSize: config.MAX_FILE_SIZE,
      files: 10
    }
  });

  // WebSocket for real-time updates
  await app.register(fastifyWebsocket);
  initializeWebSocket(app);

  // Health check
  app.get('/health', async () => ({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: config.APP_VERSION
  }));

  // Register all routes

  // Error handler
  app.setErrorHandler((error, request, reply) => {
    logger.error({ err: error, url: request.url }, 'Request error');

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

  await registerRoutes(app);

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down...');
    await shutdownQueue();
    await app.close();
    await closeDatabase();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  try {
    // Initialize database
    await initDatabase();
    logger.info('InsForge connected');

    // Initialize AI service
    await aiService.initialize();
    logger.info('AI service initialized');

    // Initialize job queue
    await initializeQueue();
    logger.info('Job queue initialized');

    // Start server
    await app.listen({ port: config.PORT, host: config.HOST });
    logger.info(`Server running on http://${config.HOST}:${config.PORT}`);
  } catch (err) {
    logger.error(err, 'Failed to start server');
    process.exit(1);
  }
}

bootstrap();