import { FastifyInstance } from 'fastify';
export declare function initializeWebSocket(app: FastifyInstance): void;
export declare function send(clientId: string, message: any): boolean;
export declare function broadcastToUser(userId: string, message: any): number;
export declare function broadcastToChannel(channel: string, message: any): number;
export declare function broadcastJobUpdate(jobId: string, update: any): void;
export declare function broadcastScanUpdate(scanId: string, update: any): void;
export declare function broadcastNotification(userId: string, notification: any): void;
export declare function getConnectedClients(): number;
//# sourceMappingURL=index.d.ts.map