import { FastifyInstance } from 'fastify';
/**
 * Sign-up, sign-in, password reset and OAuth all live in InsForge auth and are
 * called by the browser through the SDK. The API only serves the authenticated
 * user's own profile and records the session events it needs to audit.
 */
export declare function authRoutes(app: FastifyInstance): Promise<void>;
//# sourceMappingURL=routes.d.ts.map