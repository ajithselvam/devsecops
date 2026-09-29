import { FastifyInstance } from 'fastify';
import { WebSocket } from 'ws';
import { prisma } from '../database';
import { logger } from '../utils/logger';
import { verifyToken } from '../utils/auth';

interface WSClient {
  ws: WebSocket;
  userId: string;
  subscriptions: Set<string>;
}

const clients = new Map<string, WSClient>();

export function initializeWebSocket(app: FastifyInstance): void {
  app.register(async (fastify) => {
    fastify.get('/ws', { websocket: true }, async (connection, req) => {
      const ws = connection.socket;
      const query = req.query as Record<string, string | undefined>;
      const token = query.token;

      if (!token) {
        ws.close(4001, 'Authentication required');
        return;
      }

      try {
        const payload = await verifyToken(token);
        const userId = payload.sub;

        const clientId = `${userId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
        clients.set(clientId, { ws, userId, subscriptions: new Set() });

        logger.info({ userId, clientId }, 'WebSocket connected');

        ws.on('message', async (data: string | Buffer) => {
          try {
            const message = JSON.parse(data.toString());
            await handleMessage(clientId, message);
          } catch (err) {
            logger.warn({ err: err as Error, clientId }, 'Invalid WebSocket message');
          }
        });

        ws.on('close', () => {
          clients.delete(clientId);
          logger.info({ userId, clientId }, 'WebSocket disconnected');
        });

        ws.on('error', (err: Error) => {
          logger.error({ err, clientId }, 'WebSocket error');
          clients.delete(clientId);
        });

        // Send welcome message
        send(clientId, { type: 'connected', payload: { clientId }, timestamp: new Date().toISOString() });

        // Heartbeat
        const heartbeat = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.ping();
          } else {
            clearInterval(heartbeat);
          }
        }, 30000);

        ws.on('close', () => clearInterval(heartbeat));

      } catch (err) {
        logger.warn({ err }, 'WebSocket auth failed');
        ws.close(4001, 'Invalid token');
      }
    });
  });
}

async function handleMessage(clientId: string, message: any): Promise<void> {
  const client = clients.get(clientId);
  if (!client) return;

  switch (message.type) {
    case 'subscribe':
      if (message.payload?.channels) {
        for (const channel of message.payload.channels) {
          client.subscriptions.add(channel);
        }
        send(clientId, { type: 'subscribed', payload: { channels: Array.from(client.subscriptions) }, timestamp: new Date().toISOString() });
      }
      break;

    case 'unsubscribe':
      if (message.payload?.channels) {
        for (const channel of message.payload.channels) {
          client.subscriptions.delete(channel);
        }
      }
      break;

    case 'ping':
      send(clientId, { type: 'pong', payload: {}, timestamp: new Date().toISOString() });
      break;
  }
}

export function send(clientId: string, message: any): boolean {
  const client = clients.get(clientId);
  if (client && client.ws.readyState === WebSocket.OPEN) {
    client.ws.send(JSON.stringify(message));
    return true;
  }
  return false;
}

export function broadcastToUser(userId: string, message: any): number {
  let sent = 0;
  for (const [clientId, client] of clients) {
    if (client.userId === userId) {
      if (send(clientId, message)) sent++;
    }
  }
  return sent;
}

export function broadcastToChannel(channel: string, message: any): number {
  let sent = 0;
  for (const [clientId, client] of clients) {
    if (client.subscriptions.has(channel)) {
      if (send(clientId, message)) sent++;
    }
  }
  return sent;
}

export function broadcastJobUpdate(jobId: string, update: any): void {
  broadcastToChannel(`job:${jobId}`, { type: 'job_update', payload: { jobId, ...update }, timestamp: new Date().toISOString() });
}

export function broadcastScanUpdate(scanId: string, update: any): void {
  broadcastToChannel(`scan:${scanId}`, { type: 'scan_update', payload: { scanId, ...update }, timestamp: new Date().toISOString() });
}

export function broadcastNotification(userId: string, notification: any): void {
  broadcastToUser(userId, { type: 'notification', payload: notification, timestamp: new Date().toISOString() });
}

export function getConnectedClients(): number {
  return clients.size;
}