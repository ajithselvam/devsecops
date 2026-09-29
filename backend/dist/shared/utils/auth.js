"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyToken = verifyToken;
exports.bearerToken = bearerToken;
exports.authenticateRequest = authenticateRequest;
exports.ensureProfile = ensureProfile;
exports.getCurrentUser = getCurrentUser;
exports.requireAuth = requireAuth;
exports.requireRole = requireRole;
const config_1 = require("../config");
const database_1 = require("../database");
const database_2 = require("../database");
const logger_1 = require("./logger");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function verifyToken(token) {
    const key = config_1.config.INSFORGE_JWT_PUBLIC_KEY?.replace(/\\n/g, '\n');
    if (!key) {
        throw new Error('INSFORGE_JWT_PUBLIC_KEY is not configured; cannot verify InsForge sessions');
    }
    return jsonwebtoken_1.default.verify(token, key, {
        algorithms: ['RS256'],
        // InsForge signs with a rotating key pair, so accept the published `kid`.
        complete: false
    });
}
function bearerToken(request) {
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer '))
        return null;
    return header.slice(7).trim() || null;
}
function authenticateRequest(request) {
    const token = bearerToken(request);
    if (!token)
        return null;
    try {
        return verifyToken(token);
    }
    catch (err) {
        logger_1.logger.warn({ err }, 'Rejected InsForge access token');
        return null;
    }
}
/**
 * Creates the public.profiles row for a freshly authenticated InsForge user.
 * The trigger on auth.users does this too; calling the RPC keeps the profile
 * present even for users created before the trigger existed.
 */
async function ensureProfile(userId) {
    const result = await (0, database_2.getAdmin)().database.rpc('ensure_profile', { p_user_id: userId });
    if (result.error) {
        throw new Error(`ensure_profile failed: ${result.error.message}`);
    }
}
async function getCurrentUser(request) {
    const claims = authenticateRequest(request);
    if (!claims)
        return null;
    return database_1.database.user.findUnique({ where: { id: claims.sub } });
}
function requireAuth(request, reply) {
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
function requireRole(...roles) {
    return async (request, reply) => {
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
