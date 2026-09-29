"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.initializeWebSocket = initializeWebSocket;
exports.send = send;
exports.broadcastToUser = broadcastToUser;
exports.broadcastToChannel = broadcastToChannel;
exports.broadcastJobUpdate = broadcastJobUpdate;
exports.broadcastScanUpdate = broadcastScanUpdate;
exports.broadcastNotification = broadcastNotification;
exports.getConnectedClients = getConnectedClients;
const ws_1 = require("ws");
const logger_1 = require("../utils/logger");
const auth_1 = require("../utils/auth");
const clients = new Map();
function initializeWebSocket(app) {
    app.register(async (fastify) => {
        fastify.get('/ws', { websocket: true }, async (connection, req) => {
            const ws = connection.socket;
            const query = req.query;
            const token = query.token;
            if (!token) {
                ws.close(4001, 'Authentication required');
                return;
            }
            try {
                const payload = await (0, auth_1.verifyToken)(token);
                const userId = payload.sub;
                const clientId = `${userId}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
                clients.set(clientId, { ws, userId, subscriptions: new Set() });
                logger_1.logger.info({ userId, clientId }, 'WebSocket connected');
                ws.on('message', async (data) => {
                    try {
                        const message = JSON.parse(data.toString());
                        await handleMessage(clientId, message);
                    }
                    catch (err) {
                        logger_1.logger.warn({ err: err, clientId }, 'Invalid WebSocket message');
                    }
                });
                ws.on('close', () => {
                    clients.delete(clientId);
                    logger_1.logger.info({ userId, clientId }, 'WebSocket disconnected');
                });
                ws.on('error', (err) => {
                    logger_1.logger.error({ err, clientId }, 'WebSocket error');
                    clients.delete(clientId);
                });
                // Send welcome message
                send(clientId, { type: 'connected', payload: { clientId }, timestamp: new Date().toISOString() });
                // Heartbeat
                const heartbeat = setInterval(() => {
                    if (ws.readyState === ws_1.WebSocket.OPEN) {
                        ws.ping();
                    }
                    else {
                        clearInterval(heartbeat);
                    }
                }, 30000);
                ws.on('close', () => clearInterval(heartbeat));
            }
            catch (err) {
                logger_1.logger.warn({ err }, 'WebSocket auth failed');
                ws.close(4001, 'Invalid token');
            }
        });
    });
}
async function handleMessage(clientId, message) {
    const client = clients.get(clientId);
    if (!client)
        return;
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
function send(clientId, message) {
    const client = clients.get(clientId);
    if (client && client.ws.readyState === ws_1.WebSocket.OPEN) {
        client.ws.send(JSON.stringify(message));
        return true;
    }
    return false;
}
function broadcastToUser(userId, message) {
    let sent = 0;
    for (const [clientId, client] of clients) {
        if (client.userId === userId) {
            if (send(clientId, message))
                sent++;
        }
    }
    return sent;
}
function broadcastToChannel(channel, message) {
    let sent = 0;
    for (const [clientId, client] of clients) {
        if (client.subscriptions.has(channel)) {
            if (send(clientId, message))
                sent++;
        }
    }
    return sent;
}
function broadcastJobUpdate(jobId, update) {
    broadcastToChannel(`job:${jobId}`, { type: 'job_update', payload: { jobId, ...update }, timestamp: new Date().toISOString() });
}
function broadcastScanUpdate(scanId, update) {
    broadcastToChannel(`scan:${scanId}`, { type: 'scan_update', payload: { scanId, ...update }, timestamp: new Date().toISOString() });
}
function broadcastNotification(userId, notification) {
    broadcastToUser(userId, { type: 'notification', payload: notification, timestamp: new Date().toISOString() });
}
function getConnectedClients() {
    return clients.size;
}
