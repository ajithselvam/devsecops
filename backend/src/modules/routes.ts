import { FastifyInstance } from 'fastify';
import { authRoutes } from './auth/routes';
import { dockerfileRoutes } from './dockerfile/routes';
import { dockerRoutes } from './docker/routes';
import { kubernetesRoutes } from './kubernetes/routes';
import { jenkinsRoutes } from './jenkins/routes';
import { githubRoutes } from './github/routes';
import { logsRoutes } from './logs/routes';
import { dependenciesRoutes } from './dependencies/routes';
import { scansRoutes } from './scans/routes';
import { settingsRoutes } from './settings/routes';
import { aiRoutes } from './ai/routes';
import { jobsRoutes } from './jobs/routes';

export async function registerRoutes(app: FastifyInstance) {
  // API routes
  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(dockerfileRoutes, { prefix: '/api/dockerfile' });
  await app.register(dockerRoutes, { prefix: '/api/docker' });
  await app.register(kubernetesRoutes, { prefix: '/api/kubernetes' });
  await app.register(jenkinsRoutes, { prefix: '/api/jenkins' });
  await app.register(githubRoutes, { prefix: '/api/github' });
  await app.register(logsRoutes, { prefix: '/api/logs' });
  await app.register(dependenciesRoutes, { prefix: '/api/dependencies' });
  await app.register(scansRoutes, { prefix: '/api/scans' });
  await app.register(settingsRoutes, { prefix: '/api/settings' });
  await app.register(aiRoutes, { prefix: '/api/ai' });
  await app.register(jobsRoutes, { prefix: '/api/jobs' });
}