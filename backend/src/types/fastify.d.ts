import 'fastify';
import { JWTPayload } from '../shared/utils/auth';

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    user?: JWTPayload;
  }
}
