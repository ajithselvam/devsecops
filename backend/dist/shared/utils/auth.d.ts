import { FastifyRequest, FastifyReply } from 'fastify';
/**
 * Identity is owned by InsForge auth. The browser holds an InsForge session and
 * sends the access token as a bearer token; the API verifies that token with the
 * project's shared JWT secret and then reads the profile through
 * public.get_user(). Passwords are never handled here.
 */
export interface InsForgeClaims {
    sub: string;
    email?: string;
    role?: string;
    iat?: number;
    exp?: number;
    [claim: string]: unknown;
}
export declare function verifyToken(token: string): InsForgeClaims;
export declare function bearerToken(request: FastifyRequest): string | null;
export declare function authenticateRequest(request: FastifyRequest): InsForgeClaims | null;
/**
 * Creates the public.profiles row for a freshly authenticated InsForge user.
 * The trigger on auth.users does this too; calling the RPC keeps the profile
 * present even for users created before the trigger existed.
 */
export declare function ensureProfile(userId: string): Promise<void>;
export declare function getCurrentUser(request: FastifyRequest): Promise<(import("../database/types").User & Pick<{
    settings: import("../database/types").Settings;
}, never>) | null>;
export declare function requireAuth(request: FastifyRequest, reply: FastifyReply): () => Promise<InsForgeClaims | null>;
export declare function requireRole(...roles: string[]): (request: FastifyRequest, reply: FastifyReply) => Promise<InsForgeClaims | null>;
//# sourceMappingURL=auth.d.ts.map