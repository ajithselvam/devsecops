"use strict";
/**
 * Row shapes returned by the data layer.
 *
 * These mirror the legacy Prisma models (camelCase, `Date` for timestamps,
 * JSON held as strings) because the route handlers, the WebSocket payloads and
 * the React frontend all speak that contract. `passwordHash` is gone: passwords
 * now live in InsForge auth, never in the application database.
 */
Object.defineProperty(exports, "__esModule", { value: true });
