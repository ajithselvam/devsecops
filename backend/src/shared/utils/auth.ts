import { config } from '../config';
import { database } from '../database';
import { getAdmin } from '../database';
import { FastifyRequest, FastifyReply } from 'fastify';
import { logger } from './logger';
import jwt from 'jsonwebtoken';

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

export function verifyToken(token: string): InsForgeClaims {
  const key = config.INSFORGE_JWT_PUBLIC_KEY?.replace(/\\n/g, '\n');
  if (!key) {
    throw new Error('INSFORGE_JWT_PUBLIC_KEY is not configured; cannot verify InsForge sessions');
  }
  return jwt.verify(token, key, {
    algorithms: ['RS256'],
    // InsForge signs with a rotating key pair, so accept the published `kid`.
    complete: false
  }) as InsForgeClaims;
}

export function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice(7).trim() || null;
}

export function authenticateRequest(request: FastifyRequest): InsForgeClaims | null {
  const token = bearerToken(request);
  if (!token) return null;
  try {
    return verifyToken(token);
  } catch (err) {
    logger.warn({ err }, 'Rejected InsForge access token');
    return null;
  }
}

/**
 * Creates the public.profiles row for a freshly authenticated InsForge user.
 * The trigger on auth.users does this too; calling the RPC keeps the profile
 * present even for users created before the trigger existed.
 */
export async function ensureProfile(userId: string): Promise<void> {
  const result = await getAdmin().database.rpc('ensure_profile', { p_user_id: userId });
  if (result.error) {
    throw new Error(`ensure_profile failed: ${result.error.message}`);
  }
}

export async function getCurrentUser(request: FastifyRequest) {
  const claims = authenticateRequest(request);
  if (!claims) return null;
  return database.user.findUnique({ where: { id: claims.sub } });
}

export function requireAuth(request: FastifyRequest, reply: FastifyReply) {
  return async () => {
    const claims = authenticateRequest(request);
    if (!claims) {
      reply.code(401).send({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 }
      });
      return null;
    }
    return claims;
  };
}

export function requireRole(...roles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const claims = authenticateRequest(request);
    if (!claims) {
      reply.code(401).send({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required', statusCode: 401 }
      });
      return null;
    }
    if (!roles.includes(String(claims.role))) {
      reply.code(403).send({
        success: false,
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions', statusCode: 403 }
      });
      return null;
    }
    return claims;
  };
}
